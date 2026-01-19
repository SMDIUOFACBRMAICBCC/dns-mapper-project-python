"""Scan SRV strategy - Discover domains via SRV records."""

from .base import BaseStrategy, DiscoveryResult


class ScanSRVStrategy(BaseStrategy):
    """Scan SRV records for common services.
    
    SRV records document services and can reveal related domains.
    For example, _sip._tcp.se.com might reveal sipdir.online.lync.com
    """
    
    name = "scan_srv"
    description = "Scan SRV records for services"
    
    # Common services to scan
    SERVICES = [
        # Microsoft/Lync/Skype
        ('sip', 'tcp'),
        ('sip', 'udp'),
        ('sipfederationtls', 'tcp'),
        ('sipinternaltls', 'tcp'),
        
        # LDAP
        ('ldap', 'tcp'),
        ('ldaps', 'tcp'),
        ('gc', 'tcp'),  # Global Catalog
        ('kerberos', 'tcp'),
        ('kerberos', 'udp'),
        ('kpasswd', 'tcp'),
        ('kpasswd', 'udp'),
        
        # XMPP/Jabber
        ('xmpp-server', 'tcp'),
        ('xmpp-client', 'tcp'),
        ('jabber', 'tcp'),
        
        # Mail
        ('submission', 'tcp'),
        ('imap', 'tcp'),
        ('imaps', 'tcp'),
        ('pop3', 'tcp'),
        ('pop3s', 'tcp'),
        
        # CalDAV/CardDAV
        ('caldav', 'tcp'),
        ('caldavs', 'tcp'),
        ('carddav', 'tcp'),
        ('carddavs', 'tcp'),
        
        # Other
        ('http', 'tcp'),
        ('https', 'tcp'),
        ('ftp', 'tcp'),
        ('ssh', 'tcp'),
        ('telnet', 'tcp'),
        
        # Matrix
        ('matrix', 'tcp'),
        
        # Minecraft
        ('minecraft', 'tcp'),
    ]
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute SRV scanning strategy.
        
        Args:
            target: Domain to scan
            source: Source domain
            
        Returns:
            DiscoveryResult with discovered services and domains
        """
        result = DiscoveryResult()
        source = source or target
        
        for service, protocol in self.SERVICES:
            srv_records = self.resolver.query_srv(service, protocol, target)
            
            for priority, weight, port, srv_target in srv_records:
                if srv_target and srv_target.lower() != target.lower():
                    label = f"SRV/_{service}._{protocol}"
                    result.add_domain(srv_target, label, source)
                    
                    # Also resolve the SRV target to IP
                    a_records = self.resolver.query_a(srv_target)
                    for ip in a_records:
                        result.add_ip(ip, 'A', srv_target)
        
        return result
