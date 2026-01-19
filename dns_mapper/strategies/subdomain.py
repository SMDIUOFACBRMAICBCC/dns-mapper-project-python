"""Subdomain enumeration strategy - Brute-force common subdomains."""

from .base import BaseStrategy, DiscoveryResult


class SubdomainStrategy(BaseStrategy):
    """Enumerate common subdomains.
    
    Subdomains are often predictable: www, api, mail, ftp, admin, etc.
    This strategy tries common subdomain prefixes.
    """
    
    name = "subdomain"
    description = "Enumerate common subdomains"
    
    # Common subdomain prefixes
    COMMON_SUBDOMAINS = [
        # Web
        'www', 'www2', 'www3', 'web', 'portal',
        # API
        'api', 'api2', 'rest', 'graphql', 'ws', 'websocket',
        # Mail
        'mail', 'mail2', 'smtp', 'imap', 'pop', 'pop3', 'webmail', 'email', 'mx', 'mx1', 'mx2',
        # File transfer
        'ftp', 'sftp', 'files', 'download', 'uploads', 'cdn', 'static', 'assets', 'media', 'img', 'images',
        # Admin & Management
        'admin', 'administrator', 'manage', 'manager', 'panel', 'cpanel', 'whm', 'plesk', 'console',
        # Development
        'dev', 'development', 'staging', 'stage', 'test', 'testing', 'qa', 'uat', 'preprod', 'pre-prod',
        'sandbox', 'demo', 'beta', 'alpha',
        # Production
        'prod', 'production', 'live', 'app', 'apps', 'application',
        # Internal
        'internal', 'intra', 'intranet', 'extranet', 'private', 'corp', 'corporate', 'office',
        # Database
        'db', 'database', 'sql', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb', 'redis',
        # Other services
        'vpn', 'remote', 'gateway', 'gw', 'proxy', 'ns', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
        'ldap', 'ad', 'git', 'gitlab', 'github', 'bitbucket', 'svn', 'jenkins', 'ci', 'build',
        'jira', 'confluence', 'wiki', 'docs', 'help', 'support', 'helpdesk', 'ticket',
        # Cloud & hosting
        'cloud', 'server', 'server1', 'server2', 'host', 'host1', 'node', 'node1', 'cluster',
        # Auth
        'auth', 'login', 'sso', 'oauth', 'idp', 'identity', 'cas',
        # Monitoring
        'monitor', 'monitoring', 'status', 'health', 'grafana', 'kibana', 'prometheus', 'logs',
        # Blog & CMS
        'blog', 'news', 'cms', 'wordpress', 'drupal', 'joomla',
        # Shop
        'shop', 'store', 'ecommerce', 'cart', 'checkout', 'pay', 'payment',
        # Mobile
        'mobile', 'm', 'app', 'ios', 'android',
        # Security
        'secure', 'security', 'ssl', 'cert', 'autodiscover', 'autoconfig',
        # Misc
        'old', 'new', 'legacy', 'archive', 'backup', 'bak', 'temp', 'tmp',
    ]
    
    def execute(self, target: str, source: str = None) -> DiscoveryResult:
        """Execute subdomain enumeration strategy.
        
        Args:
            target: Base domain to enumerate
            source: Source domain
            
        Returns:
            DiscoveryResult with discovered subdomains
        """
        result = DiscoveryResult()
        source = source or target
        
        for prefix in self.COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{target}"
            
            # Try to resolve the subdomain
            a_records = self.resolver.query_a(subdomain)
            
            if a_records:
                result.add_domain(subdomain, 'SUBDOMAIN', source)
                
                for ip in a_records:
                    result.add_ip(ip, 'A', subdomain)
                
                # Check for CNAME
                cname = self.resolver.query_cname(subdomain)
                if cname:
                    result.add_domain(cname, 'CNAME', subdomain)
        
        return result
