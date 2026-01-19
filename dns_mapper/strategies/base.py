"""Base strategy class for DNS discovery."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Set, Dict, List, Tuple


@dataclass
class DiscoveryResult:
    """Result of a discovery strategy execution."""
    
    # Discovered domains with their record types
    # Format: {domain: [(record_type, source_domain), ...]}
    domains: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    
    # Discovered IP addresses with their record types
    # Format: {ip: [(record_type, source_domain), ...]}
    ips: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    
    # Edges for the graph: (source, target, label)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)
    
    def merge(self, other: 'DiscoveryResult') -> None:
        """Merge another result into this one."""
        for domain, records in other.domains.items():
            if domain not in self.domains:
                self.domains[domain] = []
            self.domains[domain].extend(records)
        
        for ip, records in other.ips.items():
            if ip not in self.ips:
                self.ips[ip] = []
            self.ips[ip].extend(records)
        
        self.edges.extend(other.edges)
    
    def add_domain(self, domain: str, record_type: str, source: str) -> None:
        """Add a discovered domain."""
        domain = domain.lower().rstrip('.')
        if domain not in self.domains:
            self.domains[domain] = []
        self.domains[domain].append((record_type, source))
        self.edges.append((source, domain, record_type))
    
    def add_ip(self, ip: str, record_type: str, source: str) -> None:
        """Add a discovered IP address."""
        if ip not in self.ips:
            self.ips[ip] = []
        self.ips[ip].append((record_type, source))
        self.edges.append((source, ip, record_type))
    
    def get_all_domains(self) -> Set[str]:
        """Get all discovered domains."""
        return set(self.domains.keys())
    
    def get_all_ips(self) -> Set[str]:
        """Get all discovered IPs."""
        return set(self.ips.keys())


class BaseStrategy(ABC):
    """Abstract base class for DNS discovery strategies."""
    
    name: str = "base"
    description: str = "Base strategy"
    
    def __init__(self, resolver):
        """Initialize strategy with a DNS resolver.
        
        Args:
            resolver: DNSResolver instance
        """
        self.resolver = resolver
    
    @abstractmethod
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute the discovery strategy.
        
        Args:
            target: Domain or IP to analyze
            source: Source that led to this target (for graph edges)
            
        Returns:
            DiscoveryResult with discovered domains and IPs
        """
        pass
