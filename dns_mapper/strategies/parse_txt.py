"""Parse TXT strategy - Extract domains and IPs from TXT records."""

from .base import BaseStrategy, DiscoveryResult
from ..resolver import extract_domains_from_text, extract_ips_from_text


class ParseTXTStrategy(BaseStrategy):
    """Parse TXT records to find hidden domains and IPs.
    
    TXT records often contain SPF, DKIM, DMARC info with references
    to other domains and IP addresses.
    """
    
    name = "parse_txt"
    description = "Parse TXT records for domains and IPs"
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute TXT parsing strategy.
        
        Args:
            target: Domain to analyze
            source: Source domain (unused for initial scan)
            
        Returns:
            DiscoveryResult with discovered domains and IPs
        """
        result = DiscoveryResult()
        source = source or target
        
        # Query regular TXT records
        txt_records = self.resolver.query_txt(target)
        
        # Also query DMARC record
        dmarc_records = self.resolver.query_txt(f"_dmarc.{target}")
        txt_records.extend(dmarc_records)
        
        for txt in txt_records:
            # Extract domains from TXT content
            domains = extract_domains_from_text(txt)
            for domain in domains:
                if domain.lower() != target.lower():
                    result.add_domain(domain, 'TXT', source)
            
            # Extract IPs from TXT content (often in SPF records)
            ipv4s, ipv6s = extract_ips_from_text(txt)
            for ip in ipv4s:
                result.add_ip(ip, 'TXT/SPF', source)
            for ip in ipv6s:
                result.add_ip(ip, 'TXT/SPF6', source)
        
        return result
