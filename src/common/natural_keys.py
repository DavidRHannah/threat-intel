def article_key(source_id: str, guid: str) -> str:
    return f"{source_id}::{guid}"


def ioc_key(value: str, ioc_type: str) -> str:
    return f"{value}::{ioc_type}"


def asset_key(vendor: str, product: str, version: str) -> str:
    return f"{vendor.lower()}::{product.lower()}::{version}"
