"""
Domain Utils - Утиліти для роботи з доменами
"""


def is_valid_domain(d):
    """Перевіряє чи домен валідний."""
    if not d or len(d) > 253:
        return False
    if any(c in d for c in '%{}" \n\r\t'):
        return False
    if '.' not in d:
        return False
    return True


def escape(s):
    """Escape символів для DOT формату."""
    return s.replace('\\', '').replace('"', '').replace('\n', '').replace('\r', '')


# Список TLD для фільтрації
TLDS = {
    'com', 'org', 'net', 'fr', 'uk', 'de', 'io', 'co', 
    'gov', 'edu', 'ru', 'jp', 'au', 'ca', 'us', 'eu'
}
