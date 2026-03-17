"""Provider data templates for automatic column/field configuration."""

# Each template defines:
#   pii_columns: columns that contain PII (should be anonymized)
#   keep_columns: columns that contain IOCs (should NOT be anonymized)
#   description: human-readable description

TEMPLATES = {
    "microsoft-signin": {
        "description": "Microsoft 365 Sign-In Activity logs",
        "pii_columns": ["UserPrincipalName", "DisplayName", "DeviceName"],
        "keep_columns": ["IPAddress", "Timestamp", "Location", "Status", "AppDisplayName"],
    },
    "microsoft-audit": {
        "description": "Microsoft 365 Audit Log",
        "pii_columns": ["UserId", "UserKey", "ObjectId"],
        "keep_columns": ["CreationDate", "Operation", "Workload", "ClientIP", "ResultStatus"],
    },
    "isp-connection": {
        "description": "ISP connection/session logs",
        "pii_columns": ["subscriber_name", "subscriber_email", "subscriber_address", "account_holder"],
        "keep_columns": ["source_ip", "dest_ip", "dest_port", "protocol", "timestamp", "bytes_sent", "session_duration"],
    },
    "crypto-kyc": {
        "description": "Cryptocurrency exchange KYC/account data",
        "pii_columns": ["full_name", "email", "phone", "address", "date_of_birth", "iban"],
        "keep_columns": ["user_id", "currency", "amount", "wallet_address", "ip", "transaction_id"],
    },
    "google-account": {
        "description": "Google Account activity/takeout data",
        "pii_columns": ["name", "email", "phone", "recovery_email", "recovery_phone"],
        "keep_columns": ["ip_address", "timestamp", "activity_type", "device_id"],
    },
    "telegram-user": {
        "description": "Telegram user/message data",
        "pii_columns": ["username", "first_name", "last_name", "phone_number", "bio"],
        "keep_columns": ["user_id", "date", "message_id", "chat_id", "ip_address"],
    },
    "meta-records": {
        "description": "Meta (Facebook/Instagram) subscriber records",
        "pii_columns": ["name", "email", "phone", "vanity_name", "screen_name"],
        "keep_columns": ["uid", "ip_address", "timestamp", "registration_ip", "machine_cookie"],
    },
}


def get_template(name: str) -> dict:
    """Get a template by name. Returns None if not found.

    Args:
        name: Template name, e.g. ``"microsoft-signin"``.

    Returns:
        Template dict with ``pii_columns``, ``keep_columns``, and ``description``
        keys, or ``None`` when the name is not recognised.
    """
    return TEMPLATES.get(name)


def list_templates() -> list:
    """Return list of (name, description) tuples sorted by name.

    Returns:
        Sorted list of ``(name, description)`` tuples for all registered templates.
    """
    return [(name, t["description"]) for name, t in sorted(TEMPLATES.items())]
