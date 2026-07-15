def article_key(source_id: str, guid: str) -> str:
    return f"{source_id}::{guid}"


def ioc_key(value: str, ioc_type: str) -> str:
    return f"{value}::{ioc_type}"
