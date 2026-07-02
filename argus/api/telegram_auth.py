"""
Secure Telegram authentication with HMAC verification.

This module implements the recommended Telegram Web App authentication flow
with HMAC-SHA256 verification to prevent spoofing.

Reference: https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
"""
import hashlib
import hmac
import time
from typing import Optional
from pydantic import BaseModel


class TelegramWebAppData(BaseModel):
    """Data received from Telegram Web App."""
    user: dict  # {"id": int, "first_name": str, "username": str, ...}
    auth_date: int  # Unix timestamp
    hash: str  # HMAC-SHA256 signature


def verify_telegram_data(
    telegram_data: dict,
    bot_token: str,
    max_age_seconds: int = 3600
) -> tuple[bool, Optional[str]]:
    """
    Verify Telegram Web App data using HMAC-SHA256.
    
    Args:
        telegram_data: Dictionary containing 'user', 'auth_date', and 'hash'
        bot_token: Telegram bot token
        max_age_seconds: Maximum age of auth_date (default 1 hour)
    
    Returns:
        (is_valid, error_message)
    """
    # Extract fields
    user_data = telegram_data.get("user")
    auth_date = telegram_data.get("auth_date")
    provided_hash = telegram_data.get("hash")
    
    if not all([user_data, auth_date, provided_hash]):
        return False, "Missing required fields: user, auth_date, hash"
    
    # Verify auth_date is recent (prevent replay attacks)
    current_time = int(time.time())
    if current_time - auth_date > max_age_seconds:
        return False, f"auth_date is too old (older than {max_age_seconds} seconds)"
    
    # Compute HMAC-SHA256
    # Step 1: Create secret key from bot token
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    
    # Step 2: Create data string in format: "field1=value1\nfield2=value2\n..."
    # Fields must be sorted alphabetically (excluding 'hash')
    data_pairs = []
    for key in sorted(telegram_data.keys()):
        if key != "hash":
            value = telegram_data[key]
            if isinstance(value, dict):
                # For nested objects like 'user', convert to JSON string
                import json
                value = json.dumps(value, separators=(',', ':'), sort_keys=True)
            data_pairs.append(f"{key}={value}")
    
    data_string = "\n".join(data_pairs)
    
    # Step 3: Compute HMAC
    computed_hash = hmac.new(
        secret_key,
        data_string.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Step 4: Compare hashes (constant-time comparison to prevent timing attacks)
    if not hmac.compare_digest(computed_hash, provided_hash):
        return False, "Invalid signature: HMAC verification failed"
    
    return True, None


def extract_telegram_user(telegram_data: dict) -> Optional[dict]:
    """
    Extract user information from verified Telegram data.
    
    Returns:
        Dictionary with keys: id, username, full_name, first_name, last_name, language_code
    """
    user = telegram_data.get("user", {})
    return {
        "telegram_id": user.get("id"),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "full_name": f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
        "language_code": user.get("language_code"),
        "is_bot": user.get("is_bot", False),
    }
