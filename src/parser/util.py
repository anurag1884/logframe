def safe_int_cast(val):
    try:
        return int(val)
    except ValueError:
        return val
