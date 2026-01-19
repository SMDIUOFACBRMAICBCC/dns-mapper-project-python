"""IP Neighbors strategy - Scan neighboring IP addresses."""

from .base import BaseStrategy, DiscoveryResult
from ..utils import get_ip_neighbors, is_valid_ip


class IPNeighborsStrategy(BaseStrategy):
    """Scan neighboring IP addresses.
    
    An IP address is often surrounded by other IPs from the same organization.
    Sometimes two consecutive IPs are assigned to the same company.
    
    For example, m6.fr is surrounded by RTL:
    - 92.61.160.137 (m6.fr)
    - 92.61.160.136 -> rev-160-136.rtl.fr
    - 92.61.160.138 -> rev-160-138.rtl.fr
    """
    
    name = "ip_neighbors"
    description = "Scan neighboring IP addresses"
    
    def __init__(self, resolver, neighbor_range: int = 3):
        """Initialize with neighbor range.
        
        Args:
            resolver: DNS resolver
            neighbor_range: Number of IPs to check on each side
        """
        super().__init__(resolver)
        self.neighbor_range = neighbor_range
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute IP neighbors strategy.
        
        Args:
            target: Domain or IP to analyze
            source: Source domain
            
        Returns:
            DiscoveryResult with neighbor discoveries
        """
        result = DiscoveryResult()
        source = source or target
        
        # Get IPs to analyze
        if is_valid_ip(target):
            ips_to_scan = [target]
        else:
            # Resolve domain to IPs
            ips_to_scan = self.resolver.query_a(target)
            for ip in ips_to_scan:
                result.add_ip(ip, 'A', target)
        
        # Scan neighbors for each IP
        for ip in ips_to_scan:
            neighbors = get_ip_neighbors(ip, self.neighbor_range)
            
            for neighbor_ip in neighbors:
                # Do reverse DNS on neighbor
                ptr = self.resolver.query_ptr(neighbor_ip)
                if ptr:
                    result.add_ip(neighbor_ip, 'NEIGHBOR', ip)
                    result.add_domain(ptr, 'PTR', neighbor_ip)
        
        return result
