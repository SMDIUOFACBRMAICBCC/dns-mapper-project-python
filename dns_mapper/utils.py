"""Utility functions for DNS Mapper."""

import ipaddress
from typing import Optional


# Common TLDs - used to determine where to stop crawling
# Source: https://publicsuffix.org/
COMMON_TLDS = {
    # Generic TLDs
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    # Country code TLDs
    'fr', 'de', 'uk', 'us', 'ca', 'au', 'jp', 'cn', 'ru', 'br', 'in', 'it', 'es', 'nl', 'se', 'no',
    'dk', 'fi', 'pl', 'cz', 'at', 'ch', 'be', 'pt', 'gr', 'ie', 'hu', 'ro', 'bg', 'sk', 'hr', 'si',
    'lt', 'lv', 'ee', 'ua', 'by', 'kz', 'uz', 'az', 'ge', 'am', 'md', 'kg', 'tj', 'tm',
    # Special second-level TLDs
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
    'com.au', 'org.au', 'net.au', 'edu.au', 'gov.au',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.br', 'org.br', 'net.br', 'gov.br', 'edu.br',
    'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in',
    'gouv.fr', 'asso.fr', 'com.fr',
    # New TLDs
    'io', 'co', 'ai', 'dev', 'app', 'cloud', 'tech', 'online', 'site', 'website', 'xyz',
    'info', 'biz', 'name', 'mobi', 'pro', 'tel', 'travel', 'jobs', 'museum', 'aero', 'coop'
}


def is_tld(domain: str) -> bool:
    """Check if a domain is a TLD.
    
    Args:
        domain: Domain name to check
        
    Returns:
        True if domain is a TLD
    """
    domain = domain.lower().rstrip('.')
    return domain in COMMON_TLDS


def get_parent_domain(domain: str) -> Optional[str]:
    """Get the parent domain.
    
    Args:
        domain: Domain name
        
    Returns:
        Parent domain or None if already at TLD
    """
    parts = domain.lower().rstrip('.').split('.')
    if len(parts) <= 1:
        return None
    
    # Check if current domain minus first part is a TLD
    parent = '.'.join(parts[1:])
    if is_tld(parent):
        return None
    
    return parent


def get_parent_domains(domain: str) -> list:
    """Get all parent domains up to TLD.
    
    Args:
        domain: Starting domain
        
    Returns:
        List of parent domains (not including TLD)
    """
    parents = []
    current = get_parent_domain(domain)
    while current:
        parents.append(current)
        current = get_parent_domain(current)
    return parents


def ip_to_int(ip: str) -> int:
    """Convert IP address to integer.
    
    Args:
        ip: IP address string
        
    Returns:
        Integer representation
    """
    return int(ipaddress.ip_address(ip))


def int_to_ip(num: int, version: int = 4) -> str:
    """Convert integer to IP address.
    
    Args:
        num: Integer representation
        version: IP version (4 or 6)
        
    Returns:
        IP address string
    """
    if version == 4:
        return str(ipaddress.IPv4Address(num))
    else:
        return str(ipaddress.IPv6Address(num))


def get_ip_neighbors(ip: str, range_size: int = 5) -> list:
    """Get neighboring IP addresses.
    
    Args:
        ip: Base IP address
        range_size: Number of neighbors on each side
        
    Returns:
        List of neighboring IPs
    """
    neighbors = []
    try:
        addr = ipaddress.ip_address(ip)
        version = addr.version
        base = int(addr)
        
        for offset in range(-range_size, range_size + 1):
            if offset == 0:
                continue
            try:
                neighbor = base + offset
                if version == 4:
                    if 0 <= neighbor <= 0xFFFFFFFF:
                        neighbors.append(str(ipaddress.IPv4Address(neighbor)))
                else:
                    if 0 <= neighbor <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
                        neighbors.append(str(ipaddress.IPv6Address(neighbor)))
            except Exception:
                continue
    except Exception:
        pass
    
    return neighbors


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name.
    
    Args:
        domain: String to check
        
    Returns:
        True if valid domain
    """
    if not domain or len(domain) > 253:
        return False
    
    # Must have at least one dot
    if '.' not in domain:
        return False
    
    parts = domain.split('.')
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not all(c.isalnum() or c == '-' for c in part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address.
    
    Args:
        ip: String to check
        
    Returns:
        True if valid IP
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
