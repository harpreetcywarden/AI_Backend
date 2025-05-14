# apps/storage/tasks.py
import os
import logging
import time
import shutil
import torch # Assuming GPU is available to the Celery worker

from django.conf import settings
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
from botocore.exceptions import ClientError, NoCredentialsError
import boto3
# Import text processing/embedding models and tools
from sentence_transformers import SentenceTransformer
from langchain.text_splitter import RecursiveCharacterTextSplitter
from ..worker.file_to_chromadb import *
# Import your actual file processing functions (replace placeholders)
# from .file_parsing_utils import process_pdf, process_txt, ...
# Placeholder functions - REPLACE with your actual implementations


logger = logging.getLogger(__name__)

# --- Global Variables / Clients (Load Once per Worker Process) ---
# These initialize when a Celery worker process starts.

# S3 Client (uses IAM role assumed by the worker instance)
s3_client = None
try:
    logger.info("Celery Worker: Initializing S3 client...")
    # Ensure region is configured if needed, otherwise rely on SDK defaults/role
    s3_region = getattr(settings, 'AWS_S3_REGION_NAME', None)
    s3_client = boto3.client('s3', region_name=s3_region)
    # Optional: Test connection? s3_client.list_buckets() # Requires ListBucket permission
    logger.info(f"S3 client initialized for region: {s3_region or 'default'}.")
except NoCredentialsError:
    logger.error("Celery Worker: AWS credentials not found for S3 client. Ensure IAM role is attached.")
    s3_client = None
except Exception as e:
    logger.error(f"Celery Worker: Failed to initialize S3 client: {e}", exc_info=True)
    s3_client = None

# Embedding Model
embedding_model = None
try:
    logger.info("Celery Worker: Loading embedding model...")
    # Ensure the model is accessible to the worker instance
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Embedding model loaded on device: {embedding_model.device}")
except Exception as e:
    logger.error(f"Celery Worker: Failed to load embedding model: {e}", exc_info=True)
    embedding_model = None

# Text Splitter
text_splitter = None
try:
    logger.info("Celery Worker: Initializing Text Splitter...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.CHUNK_SIZE, # Example: Get from settings
        chunk_overlap=settings.CHUNK_OVERLAP, # Example: Get from settings
        length_function=len,
        is_separator_regex=False,
    )
    logger.info(f"Text Splitter initialized (Size: {settings.CHUNK_SIZE}, Overlap: {settings.CHUNK_OVERLAP}).")
except Exception as e:
    logger.error(f"Celery Worker: Failed to initialize text splitter: {e}", exc_info=True)
    text_splitter = None


# OpenSearch Client
opensearch_client = None
try:
    OPENSEARCH_HOST = 'vpc-guruvectordb-qcasgprbdyout4otbqqkuklwdi.us-east-1.es.amazonaws.com'
    OPENSEARCH_PORT = 443
    OPENSEARCH_AUTH = ('Guruai', 'Guru_ai1')

    if not all([OPENSEARCH_HOST, OPENSEARCH_AUTH]):
         logger.error("OpenSearch Host or Auth configuration missing in Django settings.")
    else:
         logger.info(f"Initializing OpenSearch client for host {OPENSEARCH_HOST}...")
         opensearch_client = OpenSearch(
             hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
             http_auth=OPENSEARCH_AUTH,
             use_ssl=True,
             verify_certs=False, # Set to True in production with proper certs
             ssl_assert_hostname=False,
             ssl_show_warn=False,
             connection_class=RequestsHttpConnection, # Good practice
             timeout=20, # Increase default timeout
             max_retries=2,
             retry_on_timeout=True
         )
         # Test connection
         if not opensearch_client.ping():
              logger.error("OpenSearch cluster ping failed!")
              opensearch_client = None # Mark as unavailable
         else:
              logger.info("OpenSearch client initialized and ping successful.")

except Exception as e:
    logger.error(f"Celery Worker: Failed to initialize OpenSearch client: {e}", exc_info=True)
    opensearch_client = None

# --- End Global Variables ---


# --- Helper Functions ---

def get_opensearch_index_name(user_id):
    """Generates the OpenSearch index name based on the user ID."""
    # Example: prefix + user_id. Ensure valid index name characters.
    # Replace invalid characters if user_id might contain them.
    safe_user_id = str(user_id).lower().replace('-', '_') # Basic example
    return f"user_vectors_{safe_user_id}"

def create_opensearch_index_if_not_exists(client, index_name):
    """Creates the OpenSearch index with mapping if it doesn't exist."""
    if not client: return False
    try:
        if not client.indices.exists(index=index_name):
            logger.info(f"Task: Index '{index_name}' does not exist. Creating...")
            # Define mapping (ensure dimension matches your embedding_model)
            # Store s3_key and filename for reference, user_id isn't strictly needed if index is per-user
            mapping = {
                "settings": {
                    "index": {
                        "knn": True,
                        "knn.algo_param.ef_search": 100
                    }
                },
                "mappings": {
                    "properties": {
                        "embedding": {
                            "type": "knn_vector",
                            "dimension": 384, # Dimension of all-MiniLM-L6-v2
                            "method": { # Add method for indexing performance
                                "name": "hnsw",
                                "space_type": "l2", # Or cosine, etc.
                                "engine": "nmslib", # Or faiss
                                "parameters": {
                                    "ef_construction": 128,
                                    "m": 24
                                }
                             }
                        },
                        "content": {"type": "text"}, # Store the chunk text for context retrieval
                        "entry_uuid": {"type": "keyword"}, # Link back to your Django Entry UUID
                        "chunk_id": {"type": "integer"},
                        "s3_key": {"type": "keyword"},
                        "filename": {"type": "keyword"} # Use keyword if not analyzing filename text
                    }
                }
            }
            client.indices.create(index=index_name, body=mapping, ignore=[400, 404]) # Ignore if exists or creation races
            # Verify creation shortly after
            time.sleep(1) # Short delay before checking existence again
            if client.indices.exists(index=index_name):
                 logger.info(f"Task: Index '{index_name}' created or already exists.")
                 return True
            else:
                 logger.error(f"Task: Index '{index_name}' creation failed verification.")
                 return False
        else:
             # logger.debug(f"Task: Index '{index_name}' already exists.")
             return True
    except Exception as e:
         logger.error(f"Task: Failed to create or check index '{index_name}': {e}", exc_info=True)
         return False

def get_file_processor(file_extension):
    """Maps file extension to processing function."""
    ext = file_extension.lower()
    processors = {
        'pdf': process_pdf, 'txt': process_txt, 'docx': process_docx,
        'pptx': process_pptx, 'xlsx': process_xlsx, 'csv': process_csv,
        'jpg': process_image, 'jpeg': process_image, 'png': process_image
    }
    return processors.get(ext)

def generate_opensearch_actions(index_name, entry_uuid, filename, s3_key, chunks):
    """Generator function for OpenSearch bulk indexing actions."""
    if not embedding_model:
        logger.error("Embedding model not loaded, cannot generate actions.")
        return # Stop iteration

    for i, chunk_content in enumerate(chunks):
        try:
            embedding = embedding_model.encode(chunk_content).tolist()
            doc_id = f"{entry_uuid}_{i}"
            source_doc = {
                "embedding": embedding,
                "content": chunk_content,
                "entry_uuid": str(entry_uuid),
                "chunk_id": i,
                "s3_key": s3_key,
                "filename": filename
            }
            yield {
                "_index": index_name,
                "_id": doc_id,
                "_source": source_doc
            }
        except Exception as e:
             logger.error(f"Failed to process chunk {i} for embedding for entry {entry_uuid}: {e}", exc_info=True)
             # Skip this chunk

# --- The Main Celery Task ---

# Renamed task to reflect its purpose
@shared_task(bind=True, ignore_result=True, max_retries=1, default_retry_delay=120, name='process_file_task_explicit_name')
def process_and_index_file_task(self, user_id, user_email, original_filename, entry_uuid, s3_key):
    """
    Celery Task: Downloads file from S3, processes it, generates embeddings,
    and indexes them in a user-specific OpenSearch index.
    """
    task_start_time = time.time()
    logger.info(f"Task Received: Process file entry {entry_uuid} for user {user_id}")

    # --- Pre-computation Checks ---
    if not all([s3_client, embedding_model, text_splitter, opensearch_client]):
        logger.error(f"Task Aborted: Worker for entry {entry_uuid} is missing essential components (S3/Model/Splitter/OS).")
        # You might want to retry later if it's a temporary initialization issue
        # raise self.retry(countdown=300, max_retries=2) # Example: Retry in 5 mins
        return "Failed: Worker components not initialized"

    # --- Determine Index Name ---
    index_name = get_opensearch_index_name("temp_index")
    logger.info(f"Task: Using OpenSearch index '{index_name}' for user {user_id}")

    # --- Prepare Temporary File Path ---
    # Using tempfile module is safer
    import tempfile
    temp_dir = tempfile.gettempdir() # Use system temp dir
    temp_file_path = os.path.join(temp_dir, f"{entry_uuid}_{original_filename}")

    # --- Processing Steps ---
    try:
        # 1. Download file from S3
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        if not bucket_name: raise ValueError("AWS_STORAGE_BUCKET_NAME not configured")

        logger.info(f"Task: Downloading s3://{bucket_name}/{s3_key} to {temp_file_path}")
        s3_client.download_file(bucket_name, s3_key, temp_file_path)
        logger.info(f"Task: Download complete for {entry_uuid}.")

        # 2. Process the downloaded file (get text chunks)
        file_extension = original_filename.split('.')[-1]
        processor = get_file_processor(file_extension)
        if not processor:
            logger.warning(f"Task: Unsupported file type '{file_extension}' for entry {entry_uuid}. Skipping indexing.")
            # No error, just unsupported type
            return f"Skipped: Unsupported type {file_extension}"

        logger.info(f"Task: Processing file content from {temp_file_path} using {processor.__name__}")
        raw_text = processor(temp_file_path) # Expects string output
        if not isinstance(raw_text, str):
             logger.warning(f"Task: Processor for {original_filename} did not return a string. Skipping chunking.")
             chunks = []
        else:
             logger.info(f"Task: Splitting text for {entry_uuid}...")
             chunks = text_splitter.split_text(raw_text)
             logger.info(f"Task: Split into {len(chunks)} chunks for {entry_uuid}.")

        # 3. Index Chunks in OpenSearch (if any)
        if opensearch_client and chunks:
            if not create_opensearch_index_if_not_exists(opensearch_client, index_name):
                # Logged inside helper, raise specific error to trigger retry if desired
                raise Exception(f"Failed to ensure index '{index_name}' exists.")

            logger.info(f"Task: Preparing to bulk index {len(chunks)} chunks into '{index_name}'...")
            # Use bulk helper for efficiency
            success_count, errors = helpers.bulk(
                client=opensearch_client,
                actions=generate_opensearch_actions(index_name, entry_uuid, original_filename, s3_key, chunks),
                chunk_size=500, # Adjust chunk size as needed
                max_retries=2,
                initial_backoff=2,
                request_timeout=60 # Increase timeout for bulk operations
            )
            logger.info(f"Task: Bulk indexing for {entry_uuid} complete. Success: {success_count}, Errors: {len(errors)}")
            if errors:
                 logger.error(f"Task: Errors occurred during bulk indexing for {entry_uuid}: {errors[:5]}") # Log first few errors
                 # Decide if errors constitute task failure or partial success
                 # Maybe raise exception to trigger retry if there were errors?
                 # raise Exception(f"{len(errors)} errors during bulk indexing.")

        elif not chunks:
             logger.info(f"Task: No chunks generated for {entry_uuid}, skipping OpenSearch indexing.")
        else: # opensearch_client is None
             logger.error("Task: OpenSearch client not available, skipping indexing.")
             # Maybe retry? raise Exception("OpenSearch client unavailable")

        task_duration = time.time() - task_start_time
        logger.info(f"Task Completed: Processing for entry {entry_uuid}. Duration: {task_duration:.2f}s")
        return f"Success: Processed {len(chunks)} chunks in {task_duration:.2f}s"

    except ClientError as exc:
        logger.error(f"Task Failed: S3 Error during download for {s3_key}: {exc}", exc_info=True)
        # Decide if specific S3 errors are retryable
        # raise self.retry(exc=exc)
        return f"Failed: S3 Error - {exc}"
    except ValueError as exc: # Catch unsupported type or other value errors
        logger.error(f"Task Failed: Value error during processing {entry_uuid}: {exc}")
        return f"Failed: Value Error - {exc}"
    except Exception as exc: # Catch all other errors
        logger.error(f"Task Failed: Unexpected error processing entry {entry_uuid}: {exc}", exc_info=True)
        try:
            # Retry for generic errors? Be cautious.
            logger.warning(f"Task: Retrying unexpected error for entry {entry_uuid}")
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.error(f"Task: Max retries exceeded after unexpected error for {entry_uuid}.")
            return f"Failed: Max retries (Unexpected Error) - {exc}"
        except Exception as retry_exc:
             logger.error(f"Task: Error during retry mechanism: {retry_exc}")
             return f"Failed: Retry mechanism error - {retry_exc}"
    finally:
        # Cleanup temporary file ALWAYS
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logger.info(f"Task: Removed temporary file: {temp_file_path}")
            except OSError as e_rm:
                logger.error(f"Task: Error removing temporary file {temp_file_path}: {e_rm}")