"""
Supabase client configuration for PII-Safe.

Provides a singleton Supabase client for database operations.
"""

import os
from typing import Optional
from supabase import create_client, Client


SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

_client: Optional[Client] = None


def get_supabase() -> Client:
    """
    Get or create the Supabase client instance.

    Returns:
        Supabase client instance

    Raises:
        ValueError: If SUPABASE_URL or SUPABASE_KEY is not configured
    """
    global _client

    if _client is not None:
        return _client

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError(
            "Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY environment variables. "
            "You can find these in your Supabase project settings under API settings."
        )

    _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client


def init_supabase() -> Client:
    """
    Initialize the Supabase client.

    Returns:
        Supabase client instance
    """
    global _client
    _client = get_supabase()
    return _client


def close_supabase():
    """Close the Supabase client connection."""
    global _client
    _client = None
