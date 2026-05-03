"""Security helpers for the Audora GUI."""

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def escape_csv_formula(value):
    """Prefix spreadsheet formulas so exported API data cannot execute."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value
