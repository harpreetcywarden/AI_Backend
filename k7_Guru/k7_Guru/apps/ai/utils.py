# apps/ai/utils.py
import logging
import requests
from requests.exceptions import RequestException, Timeout
from django.conf import settings 

logger = logging.getLogger(__name__)

# --- Configuration ---
VECTOR_HISTORY_URL = settings.FASTAPI_SERVICE_URL
VECTOR_HISTORY_API_KEY = settings.FASTAPI_API_KEY
GENERATION_URL = settings.GENERATION_SERVICE_URL
GENERATION_API_KEY = settings.GENERATION_API_KEY
REQUEST_TIMEOUT = 30

# --- Helper for Vector/History Headers ---
def _get_vector_history_headers():
    if not VECTOR_HISTORY_API_KEY:
        logger.error("Vector/History API Key is not configured in Django settings.")
        return None
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": VECTOR_HISTORY_API_KEY
    }

# --- Helper for Generation Headers ---
def _get_generation_headers():
    if not GENERATION_API_KEY:
        logger.error("Generation API Key is not configured in Django settings.")
        return None
    # Assuming same header structure, just different key
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": GENERATION_API_KEY
    }


# --- Vector Search (Uses _get_vector_history_headers) ---
def call_vector_search(user_id: str, query: str, top_k: int = 3) -> list:
    """Calls the FastAPI /vectors/search endpoint."""
    headers = _get_vector_history_headers()
    if headers is None: return []

    endpoint = f"{VECTOR_HISTORY_URL}/vectors/search"
    payload = {"user_id": user_id, "query": query, "top_k": top_k}
    logger.info(f"Calling Vector Search: user={user_id}, top_k={top_k}, query='{query[:50]}...'")
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        response_data = response.json()
        search_results = response_data.get('results', [])
        logger.info(f"Vector Search successful. Found {len(search_results)} results.")
        return search_results
    except Timeout:
        logger.error(f"Vector Search call timed out after {REQUEST_TIMEOUT} seconds for user {user_id}.")
        return []
    except RequestException as e:
        status_code = e.response.status_code if hasattr(e, 'response') and e.response is not None else "N/A"
        response_text = e.response.text[:200] if hasattr(e, 'response') and e.response is not None else "N/A"
        logger.error(f"Vector Search call failed for user {user_id}. Status: {status_code}. Error: {e}. Response: {response_text}", exc_info=False)
        return []
    except Exception as e:
        logger.error(f"Unexpected error during Vector Search call for user {user_id}: {e}", exc_info=True)
        return []


# --- History Retrieval (Uses _get_vector_history_headers) ---
def call_history_retrieve(user_id: str, session_id: str, limit: int = 10, sort_order: str = 'desc') -> list:
    """Calls the FastAPI /chat/history/retrieve endpoint."""
    headers = _get_vector_history_headers()
    if headers is None: return []
    if 'Content-Type' in headers: del headers['Content-Type']

    endpoint = f"{VECTOR_HISTORY_URL}/chat/history/retrieve"
    params = {"user_id": user_id, "limit": limit, "sort_order": sort_order}
    if session_id: params["session_id"] = session_id
    logger.info(f"Calling History Retrieve: user={user_id}, session={session_id}, limit={limit}, sort={sort_order}")
    try:
        response = requests.get(endpoint, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        history_entries = response.json()
        logger.info(f"History Retrieve successful. Found {len(history_entries)} entries.")
        return history_entries
    except Timeout:
        logger.error(f"History Retrieve call timed out after {REQUEST_TIMEOUT} seconds for user {user_id}, session {session_id}.")
        return []
    except RequestException as e:
        status_code = e.response.status_code if hasattr(e, 'response') and e.response is not None else "N/A"
        response_text = e.response.text[:200] if hasattr(e, 'response') and e.response is not None else "N/A"
        logger.error(f"History Retrieve call failed for user {user_id}, session {session_id}. Status: {status_code}. Error: {e}. Response: {response_text}", exc_info=False)
        return []
    except Exception as e:
         logger.error(f"Unexpected error during History Retrieve call for user {user_id}, session {session_id}: {e}", exc_info=True)
         return []


# --- History Storage (Uses _get_vector_history_headers) ---
def call_history_store(user_id: str, session_id: str, human_message: str, ai_message: str) -> bool:
    """Calls the FastAPI /chat/history endpoint to store a conversation turn."""
    headers = _get_vector_history_headers()
    if headers is None: return False

    endpoint = f"{VECTOR_HISTORY_URL}/chat/history"
    payload = {"user_id": user_id, "session_id": session_id, "human_message": human_message, "ai_message": ai_message}
    logger.info(f"Calling History Store: user={user_id}, session={session_id}")
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        if response.status_code == 201:
             logger.info(f"History Store successful for user={user_id}, session={session_id}.")
             return True
        else:
             response.raise_for_status()
             logger.warning(f"History Store returned unexpected success status {response.status_code}. Treating as failure.")
             return False
    except Timeout:
        logger.error(f"History Store call timed out after {REQUEST_TIMEOUT} seconds for user {user_id}, session {session_id}.")
        return False
    except RequestException as e:
        status_code = e.response.status_code if hasattr(e, 'response') and e.response is not None else "N/A"
        response_text = e.response.text[:200] if hasattr(e, 'response') and e.response is not None else "N/A"
        logger.error(f"History Store call failed for user {user_id}, session {session_id}. Status: {status_code}. Error: {e}. Response: {response_text}", exc_info=False)
        return False
    except Exception as e:
        logger.error(f"Unexpected error during History Store call for user {user_id}, session {session_id}: {e}", exc_info=True)
        return False


def call_llm(query: str, context : str, history : str ) -> str:
    """
    Calls the FastAPI /generate endpoint on the GENERATION_SERVICE_URL
    to get the LLM response.
    """
    headers = _get_generation_headers() # Use specific headers for generation service
    if headers is None:
        # Config error, return specific message
        return "Error: LLM Generation service API Key not configured."
    if not GENERATION_URL:
        return "Error: LLM Generation service URL not configured."

    endpoint = f"{GENERATION_URL}/ask"
    # Payload matches the /ask endpoint's Body parameters
    payload = {
        "query": query,
        "context" : context,
        "history": history
        #"max_tokens": 500,  # Or adjust as needed, make configurable?
        #"temperature": 0.2 # Or adjust as needed, make configurable?
    }
    logger.info(f"Calling LLM Generation: Endpoint='{endpoint}' ...'")

    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT # Use the potentially longer timeout
        )
        response.raise_for_status() # Check for 4xx/5xx errors
        graph = None
        response_data = response.json()
        generated_text = response_data.get('response') # Extract text from 'response' key
        graph = response_data.get('graph')
        if generated_text is None:
            logger.error(f"LLM Generation call successful (Status {response.status_code}) but 'response' key missing or null in JSON.")
            return "Error: Received invalid response from LLM generation service."

        logger.info(f"LLM Generation successful. Response length: {len(generated_text)}")
        return generated_text,graph

    except Timeout:
        logger.error(f"LLM Generation call timed out after {REQUEST_TIMEOUT} seconds.")
        return "Error: The request to the AI service timed out. Please try again."
    except RequestException as e:
    # Get status code safely, default to None if no response
        status_code = e.response.status_code if hasattr(e, 'response') and e.response is not None else None
        response_text = e.response.text[:200] if hasattr(e, 'response') and e.response is not None else "No response body" # More descriptive default

        # Log the error, handling None status code
        logger.error(
            f"LLM Generation call failed. Status: {status_code if status_code is not None else 'Connection Error'}. "
            f"Error: {e}. Response snippet: {response_text}",
            exc_info=False # Set to True if you want the full traceback for RequestException in logs
        )

        # Provide a user-friendly error based on status or connection failure
        if status_code is None:
            # Handle connection errors, timeouts, etc.
            return "Error: Could not connect to the LLM generation service. Please check if it's running and accessible."
        elif status_code == 401 or status_code == 403:
            return "Error: Authentication failed with the LLM generation service."
        elif status_code >= 500:
            return "Error: The LLM generation service encountered an internal error (Status: {}). Please try again later.".format(status_code)
        elif status_code >= 400: # Handle other client-side errors from the LLM service
            return "Error: Received an error from the LLM generation service (Status: {}).".format(status_code)
        else: # Should ideally not happen if requests was successful, but good fallback
            return "Error: Received an unexpected response (Status: {}) from the LLM generation service.".format(status_code)

    except Exception as e:
        logger.error(f"Unexpected error during LLM Generation call: {e}", exc_info=True)
        return "Error: An unexpected error occurred while contacting the LLM service."