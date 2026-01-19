"""DNS Resolver wrapper using dnspython."""

import dns.resolver
import dns.reversename
import dns.exception
from typing import Optional
import re


class DNSResolver:
    """Wrapper class for DNS queries."""
    
    def __init__(self, timeout: float = 5.0, nameservers: Optional[list] = None):
        """Initialize the DNS resolver.
        
        Args:
            timeout: Query timeout in seconds
            nameservers: List of nameserver IPs to use
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        if nameservers:
            self.resolver.nameservers = nameservers
    
    def _query(self, domain: str, record_type: str) -> list:
        """Execute a DNS query.
        
        Args:
            domain: Domain name to query
            record_type: DNS record type (A, AAAA, TXT, etc.)
            
        Returns:
            List of record values
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.NoRootSOA, Exception):
            return []
    
    def query_a(self, domain: str) -> list:
        """Query A records (IPv4 addresses)."""
        return self._query(domain, 'A')
    
    def query_aaaa(self, domain: str) -> list:
        """Query AAAA records (IPv6 addresses)."""
        return self._query(domain, 'AAAA')
    
    def query_txt(self, domain: str) -> list:
        """Query TXT records."""
        results = self._query(domain, 'TXT')
        # Clean up TXT records (remove quotes)
        return [r.strip('"') for r in results]
    
    def query_mx(self, domain: str) -> list:
        """Query MX records.
        
        Returns:
            List of tuples (priority, mail server)
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [(rdata.preference, str(rdata.exchange).rstrip('.')) 
                    for rdata in answers]
        except Exception:
            return []
    
    def query_ns(self, domain: str) -> list:
        """Query NS records."""
        results = self._query(domain, 'NS')
        return [r.rstrip('.') for r in results]
    
    def query_cname(self, domain: str) -> Optional[str]:
        """Query CNAME record.
        
        Returns:
            CNAME target or None
        """
        results = self._query(domain, 'CNAME')
        if results:
            return results[0].rstrip('.')
        return None
    
    def query_srv(self, service: str, protocol: str, domain: str) -> list:
        """Query SRV records.
        
        Args:
            service: Service name (e.g., 'sip', 'ldap')
            protocol: Protocol ('tcp' or 'udp')
            domain: Domain name
            
        Returns:
            List of tuples (priority, weight, port, target)
        """
        query_name = f"_{service}._{protocol}.{domain}"
        try:
            answers = self.resolver.resolve(query_name, 'SRV')
            return [(rdata.priority, rdata.weight, rdata.port, 
                    str(rdata.target).rstrip('.')) for rdata in answers]
        except Exception:
            return []
    
    def query_soa(self, domain: str) -> Optional[dict]:
        """Query SOA record.
        
        Returns:
            Dict with SOA info or None
        """
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                return {
                    'mname': str(rdata.mname).rstrip('.'),
                    'rname': str(rdata.rname).rstrip('.'),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum
                }
        except Exception:
            return None
    
    def query_ptr(self, ip: str) -> Optional[str]:
        """Query PTR record (reverse DNS).
        
        Args:
            ip: IP address (IPv4 or IPv6)
            
        Returns:
            Domain name or None
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            for rdata in answers:
                return str(rdata).rstrip('.')
        except Exception:
            return None
    
    def query_all(self, domain: str) -> dict:
        """Query all common record types.
        
        Returns:
            Dict with all record types and their values
        """
        return {
            'A': self.query_a(domain),
            'AAAA': self.query_aaaa(domain),
            'TXT': self.query_txt(domain),
            'MX': self.query_mx(domain),
            'NS': self.query_ns(domain),
            'CNAME': self.query_cname(domain),
            'SOA': self.query_soa(domain)
        }


def extract_domains_from_text(text: str) -> set:
    """Extract domain names from text.
    
    Args:
        text: Text to parse
        
    Returns:
        Set of domain names found
    """
    # Domain pattern: word characters and hyphens, with at least one dot
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    matches = re.findall(pattern, text)
    return set(m.lower().rstrip('.') for m in matches)


def extract_ips_from_text(text: str) -> tuple:
    """Extract IP addresses from text.
    
    Args:
        text: Text to parse
        
    Returns:
        Tuple of (ipv4_set, ipv6_set)
    """
    # IPv4 pattern
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ipv4_matches = re.findall(ipv4_pattern, text)
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    ipv6_matches = re.findall(ipv6_pattern, text)
    
    return set(ipv4_matches), set(ipv6_matches)
