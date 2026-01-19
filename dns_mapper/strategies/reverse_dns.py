"""Reverse DNS strategy - Resolve IPs to domain names."""

from .base import BaseStrategy, DiscoveryResult
from ..utils import is_valid_ip


class ReverseDNSStrategy(BaseStrategy):
    """Perform reverse DNS lookups on IP addresses.
    
    After resolving a domain to IP, resolve the IP back to domain
    via PTR records. This often reveals hosting provider info.
    
    For example:
    - se.com -> 34.227.236.7
    - 34.227.236.7 -> ec2-34-227-236-7.compute-1.amazonaws.com
    """
    
    name = "reverse_dns"
    description = "Reverse DNS lookup (PTR records)"
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute reverse DNS strategy.
        
        Args:
            target: Domain or IP to analyze
            source: Source domain
            
        Returns:
            DiscoveryResult with PTR domain discoveries
        """
        result = DiscoveryResult()
        source = source or target
        
        # If target is an IP, do reverse DNS directly
        if is_valid_ip(target):
            ptr = self.resolver.query_ptr(target)
            if ptr:
                result.add_domain(ptr, 'PTR', target)
            return result
        
        # If target is a domain, first resolve to IPs then reverse
        a_records = self.resolver.query_a(target)
        aaaa_records = self.resolver.query_aaaa(target)
        
        all_ips = a_records + aaaa_records
        
        for ip in all_ips:
            result.add_ip(ip, 'A' if '.' in ip else 'AAAA', target)
            
            # Reverse DNS lookup
            ptr = self.resolver.query_ptr(ip)
            if ptr and ptr.lower() != target.lower():
                result.add_domain(ptr, 'PTR', ip)
        
        return result
