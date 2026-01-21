"""
Graph Layout - Налаштування розміщення графу
"""


def get_layout_settings(num_domains):
    """
    Повертає налаштування layout залежно від розміру графу.
    """
    if num_domains > 300:
        return {
            'ranksep': 0.8,
            'nodesep': 0.05,
            'fontsize': 7,
            'height': 0.18,
            'margin': '"0.04,0.02"',
            'max_per_layer': 50,
        }
    elif num_domains > 150:
        return {
            'ranksep': 1.0,
            'nodesep': 0.08,
            'fontsize': 8,
            'height': 0.22,
            'margin': '"0.06,0.03"',
            'max_per_layer': 80,
        }
    elif num_domains > 80:
        return {
            'ranksep': 1.2,
            'nodesep': 0.12,
            'fontsize': 9,
            'height': 0.26,
            'margin': '"0.08,0.04"',
            'max_per_layer': 120,
        }
    else:
        return {
            'ranksep': 1.5,
            'nodesep': 0.2,
            'fontsize': 10,
            'height': 0.32,
            'margin': '"0.1,0.05"',
            'max_per_layer': 200,
        }
