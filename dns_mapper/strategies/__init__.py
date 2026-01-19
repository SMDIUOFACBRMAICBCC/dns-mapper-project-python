"""Strategies package for DNS discovery."""

from .base import BaseStrategy, DiscoveryResult
from .parse_txt import ParseTXTStrategy
from .crawl_tld import CrawlTLDStrategy
from .scan_srv import ScanSRVStrategy
from .reverse_dns import ReverseDNSStrategy
from .ip_neighbors import IPNeighborsStrategy
from .subdomain import SubdomainStrategy

__all__ = [
    'BaseStrategy',
    'DiscoveryResult',
    'ParseTXTStrategy',
    'CrawlTLDStrategy',
    'ScanSRVStrategy',
    'ReverseDNSStrategy',
    'IPNeighborsStrategy',
    'SubdomainStrategy'
]

# All available strategies
ALL_STRATEGIES = {
    'parse_txt': ParseTXTStrategy,
    'crawl_tld': CrawlTLDStrategy,
    'scan_srv': ScanSRVStrategy,
    'reverse_dns': ReverseDNSStrategy,
    'ip_neighbors': IPNeighborsStrategy,
    'subdomain': SubdomainStrategy
}
