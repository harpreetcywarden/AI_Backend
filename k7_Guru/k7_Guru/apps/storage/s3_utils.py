import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError
from django.conf import settings

logger = logging.getLogger(__name__)

def get_s3_client():
    """Initializes and returns an S3 client using Django settings and IAM Role."""
    # REMOVED explicit key check - rely on Boto3 finding role credentials
    try:
         client = boto3.client(
            's3',
            region_name=settings.AWS_S3_REGION_NAME,
            config=boto3.session.Config(signature_version=settings.AWS_S3_SIGNATURE_VERSION)
        )
         return client
    except NoCredentialsError:
         logger.error("AWS credentials not found by Boto3. Ensure IAM role is attached and configured correctly.")
         return None
    except Exception as e:
         logger.error(f"Unexpected error creating S3 client: {e}")
         return None


def upload_to_s3(file_obj, s3_key):
    """Uploads a file object to S3."""
    s3_client = get_s3_client()
    if not s3_client: return False

    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    if not bucket_name:
         logger.error("AWS_STORAGE_BUCKET_NAME not configured.")
         return False

    try:
        file_obj.seek(0)
        s3_client.upload_fileobj(
            file_obj,
            bucket_name,
            s3_key
        )
        logger.info(f"Successfully uploaded to S3: s3://{bucket_name}/{s3_key}")
        return True
    except ClientError as e:
        logger.error(f"Error uploading file to S3 (s3://{bucket_name}/{s3_key}): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during S3 upload (s3://{bucket_name}/{s3_key}): {e}")
        return False

def delete_from_s3(s3_key):
    """Deletes a single file object from S3."""
    s3_client = get_s3_client()
    if not s3_client: return False

    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    if not bucket_name:
         logger.error("AWS_STORAGE_BUCKET_NAME not configured.")
         return False

    try:
        s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
        logger.info(f"Successfully deleted from S3: s3://{bucket_name}/{s3_key}")
        return True
    except ClientError as e:
        logger.error(f"Error deleting file from S3 (s3://{bucket_name}/{s3_key}): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during S3 delete (s3://{bucket_name}/{s3_key}): {e}")
        return False

def delete_multiple_from_s3(s3_keys):
    """Deletes multiple file objects from S3 efficiently."""
    if not s3_keys:
        logger.debug("No S3 keys provided for deletion.")
        return True

    s3_client = get_s3_client()
    if not s3_client: return False

    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    if not bucket_name:
         logger.error("AWS_STORAGE_BUCKET_NAME not configured.")
         return False

    objects_to_delete = [{'Key': key} for key in s3_keys]
    logger.debug(f"Preparing to delete {len(objects_to_delete)} objects from S3 bucket {bucket_name}.")

    try:
        response = s3_client.delete_objects(
            Bucket=bucket_name,
            Delete={'Objects': objects_to_delete, 'Quiet': False}
        )
        errors = response.get('Errors', [])
        if errors:
            for error in errors:
                logger.error(f"Error deleting {error['Key']} from S3: {error['Code']} - {error['Message']}")
            # Consider this a partial or full failure
            return False
        deleted_count = len(response.get('Deleted', []))
        logger.info(f"Successfully deleted {deleted_count} objects from S3 bucket {bucket_name}.")
        # Check if deleted count matches requested count (minus errors)
        if deleted_count != len(objects_to_delete) - len(errors):
             logger.warning(f"Mismatch in S3 deletion count. Requested: {len(objects_to_delete)}, Deleted: {deleted_count}, Errors: {len(errors)}")
        return True # Return True even on partial success, errors logged above
    except ClientError as e:
        logger.error(f"ClientError deleting multiple files from S3 (bucket: {bucket_name}): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during multiple S3 delete (bucket: {bucket_name}): {e}")
        return False

def copy_s3_object(source_key, destination_key):
    """Copies an object within the same S3 bucket."""
    s3_client = get_s3_client()
    if not s3_client: return False

    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    if not bucket_name:
         logger.error("AWS_STORAGE_BUCKET_NAME not configured.")
         return False

    copy_source = {'Bucket': bucket_name, 'Key': source_key}
    logger.debug(f"Attempting to copy S3 object from {source_key} to {destination_key} in bucket {bucket_name}")

    try:
        s3_client.copy_object(
            Bucket=bucket_name,
            CopySource=copy_source,
            Key=destination_key
        )
        logger.info(f"Successfully copied S3 object from s3://{bucket_name}/{source_key} to s3://{bucket_name}/{destination_key}")
        return True
    except ClientError as e:
        # Check for specific errors like NoSuchKey for the source
        if e.response['Error']['Code'] == 'NoSuchKey':
             logger.error(f"Source key not found during S3 copy: s3://{bucket_name}/{source_key}")
        else:
             logger.error(f"ClientError copying S3 object from {source_key} to {destination_key}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during S3 copy ({source_key} -> {destination_key}): {e}")
        return False

def generate_presigned_download_url(s3_key, expiration=3600):
    """
    Generates a presigned URL for downloading a private S3 object.

    :param s3_key: The key of the object in S3.
    :param expiration: Time in seconds for the presigned URL to remain valid. Default 1 hour.
    :return: Presigned URL as string, or None if error.
    """
    s3_client = get_s3_client()
    if not s3_client:
        return None

    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    if not bucket_name:
        logger.error("AWS_STORAGE_BUCKET_NAME not configured for presigned URL.")
        return None

    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
            ExpiresIn=expiration
        )
        logger.info(f"Generated presigned download URL for key: {s3_key}")
        return response
    except ClientError as e:
        logger.error(f"Error generating presigned URL for {s3_key}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error generating presigned URL for {s3_key}: {e}")
        return None