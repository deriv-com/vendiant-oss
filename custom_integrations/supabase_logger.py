#!/usr/bin/env python3
"""
Supabase LLM Call Logger
Tracks and stores LLM API calls in Supabase for analysis and monitoring.
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    from supabase import create_client, Client
    from postgrest.exceptions import APIError
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    APIError = None
    print("Warning: supabase-py not installed. Install with: pip install supabase")

# Configure logging
logger = logging.getLogger(__name__)

class SupabaseLLMLogger:
    """Logger for tracking LLM API calls in Supabase"""

    def __init__(self):
        if not SUPABASE_AVAILABLE:
            logger.warning("supabase-py package not installed. Install with: pip install supabase>=2.0.0")
            logger.warning("Supabase LLM logging disabled.")
            self.client = None
            return

        # Supabase configuration
        self.supabase_url = os.getenv('SUPABASE_URL')
        self.supabase_key = os.getenv('SUPABASE_API_KEY')
        self.auth_email = os.getenv('SUPABASE_AUTH_EMAIL')
        self.auth_password = os.getenv('SUPABASE_AUTH_PASSWORD')

        if not all([self.supabase_url, self.supabase_key, self.auth_email, self.auth_password]):
            logger.warning("Supabase configuration incomplete. Missing required environment variables.")
            logger.warning("Required: SUPABASE_URL, SUPABASE_API_KEY, SUPABASE_AUTH_EMAIL, SUPABASE_AUTH_PASSWORD")
            logger.warning("Supabase LLM logging disabled.")
            self.client = None
            return

        try:
            # Initialize Supabase client
            self.client: Client = create_client(self.supabase_url, self.supabase_key)

            # Authenticate
            auth_response = self.client.auth.sign_in_with_password({
                "email": self.auth_email,
                "password": self.auth_password
            })

            if auth_response.user:
                logger.info("Supabase LLM logger initialized successfully")
            else:
                logger.error("Supabase authentication failed")
                self.client = None

        except Exception as e:
            logger.error(f"Failed to initialize Supabase LLM logger: {e}")
            self.client = None

    def log_llm_call(self,
                     model: str,
                     provider: str,
                     request_data: Optional[Dict[str, Any]] = None,
                     response_data: Optional[Dict[str, Any]] = None,
                     error_message: Optional[str] = None,
                     duration_ms: Optional[int] = None,
                     context: Optional[Dict[str, Any]] = None,
                     service: Optional[str] = None) -> bool:
        """
        Log an LLM API call to Supabase

        Args:
            model: LLM model name (e.g., 'gpt-4o-mini', 'gemini-2.5-pro')
            provider: LLM provider (e.g., 'openai', 'litellm', 'gemini')
            request_data: Request payload/metadata
            response_data: Response payload/metadata
            error_message: Error message if call failed
            duration_ms: Request duration in milliseconds
            context: Additional context (domain, operation type, etc.)
            service: Service name (e.g., 'ai_analytics', 'news_incidents')

        Returns:
            bool: True if logged successfully, False otherwise
        """

        if not self.client:
            logger.warning("Supabase client not available. Cannot log LLM call.")
            return False

        try:
            # Prepare log entry
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "vendiant",  # Always vendiant for this platform
                "service": service or "unknown",  # ai_analytics or news_incidents
                "model": model,
                "provider": provider,
                "success": response_data is not None and error_message is None,
                "error_message": error_message,
                "duration_ms": duration_ms,  # Request duration in milliseconds
                "request_data": json.dumps(request_data) if request_data else None,
                "response_data": json.dumps(response_data) if response_data else None,
                "context": json.dumps(context) if context else None
            }

            logger.info(f"Attempting to insert LLM call log into Supabase: model={model}, provider={provider}, service={service or 'unknown'}")

            # Insert into Supabase (assuming table name is 'llm_call_logs')
            response = self.client.table('llm_call_logs').insert(log_entry).execute()

            if response.data:
                record_id = response.data[0].get('id') if response.data and isinstance(response.data[0], dict) else 'unknown'
                logger.info(f"[SUPABASE SUCCESS] LLM call logged successfully: model={model}, provider={provider}, service={service or 'unknown'}, record_id={record_id}")
                return True
            else:
                logger.warning(f"[SUPABASE WARNING] LLM call logging returned no data from Supabase. Response: {response}")
                return False

        except APIError as api_err:
            # Handle Supabase API errors specifically
            error_msg = str(api_err)
            # Try to extract error code from various possible formats
            error_code = None
            if hasattr(api_err, 'code'):
                error_code = api_err.code
            elif api_err.args and isinstance(api_err.args[0], dict):
                error_code = api_err.args[0].get('code')
            elif isinstance(error_msg, dict):
                error_code = error_msg.get('code')
            
            if error_code == 404:
                logger.error(f"[SUPABASE ERROR] Table 'llm_call_logs' not found (404). Please create the table in Supabase.")
                logger.error(f"  Table name: llm_call_logs")
                logger.error(f"  Required columns: timestamp, source, service, model, provider, success, error_message, duration_ms, request_data, response_data, context")
            else:
                logger.error(f"[SUPABASE ERROR] API error (code: {error_code}): {error_msg}")
            return False
            
        except Exception as e:
            logger.error(f"[SUPABASE ERROR] Unexpected error logging LLM call: {type(e).__name__}: {e}")
            return False


# Global logger instance
_supabase_logger = None

def get_supabase_logger() -> Optional[SupabaseLLMLogger]:
    """Get or create the global Supabase logger instance"""
    global _supabase_logger

    if _supabase_logger is None:
        try:
            _supabase_logger = SupabaseLLMLogger()
        except Exception as e:
            # Only log unexpected errors (not ImportError which is handled in __init__)
            logger.error(f"Unexpected error initializing Supabase LLM logger: {e}", exc_info=True)
            _supabase_logger = None

    return _supabase_logger

def log_llm_call(model: str,
                 provider: str,
                 request_data: Optional[Dict[str, Any]] = None,
                 response_data: Optional[Dict[str, Any]] = None,
                 error_message: Optional[str] = None,
                 duration_ms: Optional[int] = None,
                 context: Optional[Dict[str, Any]] = None,
                 service: Optional[str] = None) -> bool:
    """
    Convenience function to log LLM calls
    
    Args:
        model: LLM model name
        provider: LLM provider
        request_data: Request payload/metadata
        response_data: Response payload/metadata
        error_message: Error message if call failed
        duration_ms: Request duration in milliseconds
        context: Additional context (domain, operation type, etc.)
        service: Service name (e.g., 'ai_analytics', 'news_incidents')

    Returns:
        bool: True if logged successfully, False otherwise
    """

    logger = get_supabase_logger()
    if not logger:
        return False

    return logger.log_llm_call(
        model=model,
        provider=provider,
        request_data=request_data,
        response_data=response_data,
        error_message=error_message,
        duration_ms=duration_ms,
        context=context,
        service=service
    )
