"""Crawl to TLD strategy - Discover parent domains."""

from .base import BaseStrategy, DiscoveryResult
from ..utils import get_parent_domains


class CrawlTLDStrategy(BaseStrategy):
    """Crawl up to parent domains until TLD.
    
    For example, from 'sirena.integration.dev.atlas.fabrique.social.gouv.fr'
    discovers:
    - integration.dev.atlas.fabrique.social.gouv.fr
    - dev.atlas.fabrique.social.gouv.fr
    - atlas.fabrique.social.gouv.fr
    - fabrique.social.gouv.fr
    - social.gouv.fr
    """
    
    name = "crawl_tld"
    description = "Discover parent domains up to TLD"
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute crawl to TLD strategy.
        
        Args:
            target: Starting domain
            source: Source domain
            
        Returns:
            DiscoveryResult with parent domains
        """
        result = DiscoveryResult()
        source = source or target
        
        # Get all parent domains
        parents = get_parent_domains(target)
        
        for parent in parents:
            # Verify parent domain exists by checking if it has NS or SOA records
            ns_records = self.resolver.query_ns(parent)
            soa = self.resolver.query_soa(parent)
            
            if ns_records or soa:
                result.add_domain(parent, 'PARENT', source)
                
                # Also get A records for parent
                a_records = self.resolver.query_a(parent)
                for ip in a_records:
                    result.add_ip(ip, 'A', parent)
        
        return result
