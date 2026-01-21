"""
Graph Colors - Кольори для графу
"""

# Colors by layer (depth level)
LAYER_COLORS = [
    '#ef4444',  # Layer 0: Red (target)
    '#f97316',  # Layer 1: Orange
    '#eab308',  # Layer 2: Yellow
    '#22c55e',  # Layer 3: Green
    '#14b8a6',  # Layer 4: Teal
    '#3b82f6',  # Layer 5: Blue
    '#8b5cf6',  # Layer 6: Violet
    '#ec4899',  # Layer 7: Pink
    '#6b7280',  # Layer 8+: Gray
]

# Colors by edge type
EDGE_COLORS = {
    'MX': '#f87171',      # Red - Mail servers
    'NS': '#60a5fa',      # Blue - DNS servers
    'SOA': '#a78bfa',     # Purple - Authority
    'CNAME': '#2dd4bf',   # Teal - Aliases
    'SPF': '#fb923c',     # Orange - SPF/DMARC
    'SRV': '#f472b6',     # Pink - Services
    'SUB': '#4ade80',     # Green - Subdomains
    'PARENT': '#6b7280',  # Gray - Parent
    'DMARC': '#fbbf24',   # Yellow - DMARC
}


def get_layer_color(layer_num):
    """Get color by layer number."""
    if layer_num >= len(LAYER_COLORS):
        return LAYER_COLORS[-1]
    return LAYER_COLORS[layer_num]


def get_edge_color(rtype):
    """Get color by edge type."""
    return EDGE_COLORS.get(rtype, '#6b7280')
