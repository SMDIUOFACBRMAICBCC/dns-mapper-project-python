# config dns - sous domaines a tester
SUBS = [
    # basiques
    'www', 'www2', 'www3',
    'web', 'site', 'home',
    
    # mail
    'mail', 'mail2', 'webmail', 'smtp', 'imap', 'pop', 'pop3',
    'mx', 'mx1', 'mx2', 'exchange', 'owa', 'autodiscover',
    
    # fichiers
    'ftp', 'sftp', 'files', 'download', 'upload',
    'cdn', 'static', 'assets', 'media', 'images',
    
    # api/dev
    'api', 'api2', 'rest', 'graphql',
    'dev', 'test', 'staging', 'uat', 'demo', 'beta', 'sandbox',
    
    # admin
    'admin', 'panel', 'cpanel', 'whm',
    'dashboard', 'manage', 'console', 'control',
    
    # apps
    'portal', 'app', 'mobile', 'm',
    'client', 'customer', 'user', 'account',
    
    # vpn/remote
    'vpn', 'vpn2', 'remote', 'gateway',
    'proxy', 'citrix', 'rdp', 'ssh',
    
    # dns
    'ns', 'ns1', 'ns2', 'ns3', 'ns4',
    'dns', 'dns1', 'dns2',
    
    # db
    'db', 'db1', 'db2', 'mysql', 'postgres', 'mongo', 'redis', 'sql',
    
    # devops
    'git', 'gitlab', 'github', 'bitbucket',
    'jenkins', 'ci', 'docker', 'k8s', 'kubernetes',
    
    # collab
    'jira', 'confluence', 'wiki', 'docs',
    'slack', 'teams', 'chat', 'meet',
    
    # monitoring
    'monitor', 'status', 'grafana', 'kibana',
    'logs', 'metrics', 'nagios', 'zabbix',
    
    # security
    'secure', 'auth', 'login', 'sso', 'oauth',
    'ldap', 'ad', 'directory',
    
    # autres
    'blog', 'news', 'forum', 'shop', 'store', 'pay',
    'backup', 'old', 'new', 'legacy',
    'intranet', 'internal', 'corp', 'office',
    'cloud', 'server', 'host', 'node', 'vps',
]

SRV = [('sip','tcp'),('sip','udp'),('xmpp-server','tcp'),('ldap','tcp')]

TLDS = {'com','org','net','fr','uk','de','io','co','gov','edu','ru','jp','au','ca','us','eu'}
