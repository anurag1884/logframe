def safe_int_cast(val: str) -> str | int:
    try:
        return int(val)
    except ValueError:
        return val
