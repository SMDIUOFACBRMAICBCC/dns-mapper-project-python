# requetes dns
import re
import dns.resolver
import dns.reversename
from dns_config import SUBS, SRV, TLDS


def query(domain, rtype):
    # fait une requete dns simple
    try:
        r = dns.resolver.Resolver()
        r.nameservers = ['8.8.8.8', '1.1.1.1']
        r.timeout = 2
        r.lifetime = 4
        res = r.resolve(domain, rtype)
        out = []
        for a in res:
            out.append(str(a))
        return out
    except:
        return []


def reverse_dns(ip):
    # ip vers domaine (ptr)
    try:
        rev = dns.reversename.from_address(ip)
        r = dns.resolver.Resolver()
        r.nameservers = ['8.8.8.8', '1.1.1.1']
        r.timeout = 2
        r.lifetime = 4
        res = r.resolve(rev, 'PTR')
        for ptr in res:
            return str(ptr).rstrip('.')
    except:
        pass
    return None


def valid(d):
    # check domaine valide
    if not d or len(d) >= 254 or '.' not in d:
        return False
    for c in '%{}" \n\r\t':
        if c in d:
            return False
    return True


def scan_one(d, check_subs=False):
    # scan un domaine et retourne les trucs trouvé
    found = set()
    edges = []
    
    # mx
    for mx in query(d, 'MX'):
        h = mx.split()[-1].rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'MX'))
    
    # ns
    for ns in query(d, 'NS'):
        h = ns.rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'NS'))
    
    # soa
    for soa in query(d, 'SOA'):
        h = soa.split()[0].rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'SOA'))
    
    # cname
    for cn in query(d, 'CNAME'):
        h = cn.rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'CNAME'))
    
    # txt et spf
    all_txt = query(d, 'TXT') + query('_dmarc.' + d, 'TXT')
    for txt in all_txt:
        # includes
        for inc in re.findall(r'include:([a-zA-Z0-9._-]+)', txt):
            if valid(inc):
                found.add(inc)
                edges.append((d, inc, 'SPF'))
        # domaines dans txt
        for dom in re.findall(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', txt):
            if valid(dom) and dom != d:
                found.add(dom)
                edges.append((d, dom, 'TXT'))
    
    # srv
    for item in SRV:
        nom = '_' + item[0] + '._' + item[1] + '.' + d
        for srv in query(nom, 'SRV'):
            parts = srv.split()
            if len(parts) >= 4:
                h = parts[3].rstrip('.')
                if valid(h):
                    found.add(h)
                    edges.append((d, h, 'SRV'))
    
    # reverse dns et voisins ip
    for ip in query(d, 'A'):
        # ptr
        rev = reverse_dns(ip)
        if rev and valid(rev) and rev != d:
            found.add(rev)
            edges.append((d, rev, 'PTR'))
        
        # neighbors
        parts = ip.split('.')
        if len(parts) == 4:
            base = parts[0] + '.' + parts[1] + '.' + parts[2] + '.'
            last = int(parts[3])
            for n in [last - 1, last + 1]:
                if 0 <= n <= 255:
                    rev = reverse_dns(base + str(n))
                    if rev and valid(rev) and rev != d:
                        found.add(rev)
                        edges.append((d, rev, 'NEIGHBOR'))
    
    # sous domaines
    if check_subs:
        for sub in SUBS:
            sd = sub + '.' + d
            if query(sd, 'A'):
                found.add(sd)
                edges.append((d, sd, 'SUB'))
    
    # parent domain
    parts = d.split('.')
    if len(parts) > 2:
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent not in TLDS and len(parent) > 4:
                found.add(parent)
                edges.append((d, parent, 'PARENT'))
                break
    
    return found, edges
