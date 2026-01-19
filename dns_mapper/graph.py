"""Graphviz graph generation for DNS mapping results."""

from graphviz import Digraph
from typing import Dict, List, Set, Tuple
import os


class DNSGraph:
    """Generate Graphviz graphs from DNS discovery results."""
    
    # Color scheme for different node types
    COLORS = {
        'domain': '#4A90D9',      # Blue for domains
        'ip': '#50C878',          # Green for IPs
        'target': '#FF6B6B',      # Red for target domain
        'external': '#9B59B6',    # Purple for external domains
    }
    
    # Edge colors by record type
    EDGE_COLORS = {
        'A': '#2ECC71',           # Green
        'AAAA': '#27AE60',        # Dark green
        'CNAME': '#3498DB',       # Blue
        'MX': '#E74C3C',          # Red
        'NS': '#9B59B6',          # Purple
        'TXT': '#F39C12',         # Orange
        'SRV': '#1ABC9C',         # Teal
        'PTR': '#95A5A6',         # Gray
        'PARENT': '#8E44AD',      # Dark purple
        'SUBDOMAIN': '#2980B9',   # Dark blue
        'NEIGHBOR': '#7F8C8D',    # Dark gray
    }
    
    def __init__(self, target_domain: str, engine: str = 'dot'):
        """Initialize the graph.
        
        Args:
            target_domain: The main domain being analyzed
            engine: Graphviz layout engine (dot, neato, circo, twopi, fdp, sfdp)
        """
        self.target_domain = target_domain.lower()
        self.graph = Digraph(
            name='DNS Map',
            comment=f'DNS environment map for {target_domain}',
            engine=engine,
            format='png'
        )
        
        # Graph attributes for better visualization
        self.graph.attr(
            rankdir='LR',
            bgcolor='#1a1a2e',
            fontcolor='white',
            fontname='Arial',
            label=f'DNS Map: {target_domain}',
            labelloc='t',
            fontsize='20',
            pad='0.5',
            nodesep='0.5',
            ranksep='1.0'
        )
        
        # Node defaults
        self.graph.attr('node',
            shape='box',
            style='rounded,filled',
            fontname='Arial',
            fontsize='10',
            fontcolor='white'
        )
        
        # Edge defaults
        self.graph.attr('edge',
            fontname='Arial',
            fontsize='8',
            fontcolor='#cccccc'
        )
        
        self.added_nodes: Set[str] = set()
        self.added_edges: Set[Tuple[str, str, str]] = set()
    
    def _get_node_color(self, node: str, is_ip: bool = False) -> str:
        """Get color for a node based on its type."""
        if node.lower() == self.target_domain:
            return self.COLORS['target']
        elif is_ip:
            return self.COLORS['ip']
        else:
            return self.COLORS['domain']
    
    def _get_edge_color(self, record_type: str) -> str:
        """Get color for an edge based on record type."""
        # Extract base record type (e.g., 'SRV/_sip._tcp' -> 'SRV')
        base_type = record_type.split('/')[0].split('_')[0].upper()
        return self.EDGE_COLORS.get(base_type, '#cccccc')
    
    def add_node(self, node: str, is_ip: bool = False) -> None:
        """Add a node to the graph.
        
        Args:
            node: Node identifier (domain or IP)
            is_ip: Whether this is an IP address
        """
        if node in self.added_nodes:
            return
        
        color = self._get_node_color(node, is_ip)
        shape = 'ellipse' if is_ip else 'box'
        
        # Truncate long labels
        label = node if len(node) <= 40 else node[:37] + '...'
        
        self.graph.node(
            node,
            label=label,
            fillcolor=color,
            shape=shape
        )
        self.added_nodes.add(node)
    
    def add_edge(self, source: str, target: str, label: str,
                 source_is_ip: bool = False, target_is_ip: bool = False) -> None:
        """Add an edge to the graph.
        
        Args:
            source: Source node
            target: Target node
            label: Edge label (record type)
            source_is_ip: Whether source is an IP
            target_is_ip: Whether target is an IP
        """
        edge_key = (source, target, label)
        if edge_key in self.added_edges:
            return
        
        # Ensure nodes exist
        self.add_node(source, source_is_ip)
        self.add_node(target, target_is_ip)
        
        color = self._get_edge_color(label)
        
        # Shorten label for display
        short_label = label.split('/')[-1] if '/' in label else label
        
        self.graph.edge(
            source, target,
            label=short_label,
            color=color,
            fontcolor=color
        )
        self.added_edges.add(edge_key)
    
    def build_from_results(self, domains: Dict[str, List], 
                           ips: Dict[str, List],
                           edges: List[Tuple[str, str, str]]) -> None:
        """Build graph from discovery results.
        
        Args:
            domains: Dict of domains with their record info
            ips: Dict of IPs with their record info
            edges: List of (source, target, label) tuples
        """
        # Add target domain first
        self.add_node(self.target_domain)
        
        # Add all domains
        for domain in domains:
            self.add_node(domain.lower())
        
        # Add all IPs
        for ip in ips:
            self.add_node(ip, is_ip=True)
        
        # Add all edges
        for source, target, label in edges:
            source_is_ip = source in ips
            target_is_ip = target in ips
            self.add_edge(source, target, label, source_is_ip, target_is_ip)
    
    def render(self, output_path: str, format: str = 'png') -> str:
        """Render the graph to a file.
        
        Args:
            output_path: Output file path (without extension)
            format: Output format (png, svg, pdf, dot)
            
        Returns:
            Path to the generated file
        """
        self.graph.format = format
        
        # For DOT format, just save the source
        if format == 'dot':
            dot_path = f"{output_path}.dot"
            with open(dot_path, 'w', encoding='utf-8') as f:
                f.write(self.graph.source)
            return dot_path
        
        # Render to image
        return self.graph.render(output_path, cleanup=True)
    
    def get_dot_source(self) -> str:
        """Get the DOT source code."""
        return self.graph.source


def create_graph(target: str, domains: Dict, ips: Dict, 
                 edges: List, engine: str = 'dot') -> DNSGraph:
    """Create a DNS graph from results.
    
    Args:
        target: Target domain
        domains: Discovered domains
        ips: Discovered IPs
        edges: Graph edges
        engine: Graphviz engine
        
    Returns:
        DNSGraph instance
    """
    graph = DNSGraph(target, engine)
    graph.build_from_results(domains, ips, edges)
    return graph
