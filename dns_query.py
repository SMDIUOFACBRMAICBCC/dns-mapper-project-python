# requetes dns
import re
import dns.resolver
import dns.reversename
from dns_config import SUBS, SRV, TLDS


def query(domain, rtype):
    # fait une requete dns
    try:
        r = dns.resolver.Resolver()
        r.nameservers = ['8.8.8.8', '1.1.1.1']
        r.timeout = 2
        r.lifetime = 4
        result = r.resolve(domain, rtype)
        liste = []
        for a in result:
            liste.append(str(a))
        return liste
    except:
        return []


def reverse_dns(ip):
    # reverse dns - ip vers domaine
    try:
        rev_name = dns.reversename.from_address(ip)
        r = dns.resolver.Resolver()
        r.nameservers = ['8.8.8.8', '1.1.1.1']
        r.timeout = 2
        r.lifetime = 4
        result = r.resolve(rev_name, 'PTR')
        for ptr in result:
            return str(ptr).rstrip('.')
    except:
        pass
    return None


def valid(d):
    # verifie si domaine ok
    if not d:
        return False
    if len(d) >= 254:
        return False
    if '.' not in d:
        return False
    bad_chars = '%{}" \n\r\t'
    for c in bad_chars:
        if c in d:
            return False
    return True


def scan_one(d, check_subs=False):
    # scan un domaine
    found = set()
    edges = []
    
    # mx - serveur mail
    mx_records = query(d, 'MX')
    for mx in mx_records:
        parts = mx.split()
        h = parts[-1].rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'MX'))
    
    # ns - serveur dns
    ns_records = query(d, 'NS')
    for ns in ns_records:
        h = ns.rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'NS'))
    
    # soa
    soa_records = query(d, 'SOA')
    for soa in soa_records:
        parts = soa.split()
        h = parts[0].rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'SOA'))
    
    # cname - alias
    cname_records = query(d, 'CNAME')
    for cn in cname_records:
        h = cn.rstrip('.')
        if valid(h):
            found.add(h)
            edges.append((d, h, 'CNAME'))
    
    # txt/spf - parse les includes
    txt_records = query(d, 'TXT')
    dmarc_records = query('_dmarc.' + d, 'TXT')
    all_txt = txt_records + dmarc_records
    for txt in all_txt:
        # cherche include:domaine
        includes = re.findall(r'include:([a-zA-Z0-9._-]+)', txt)
        for inc in includes:
            if valid(inc):
                found.add(inc)
                edges.append((d, inc, 'SPF'))
        # cherche des domaines dans le txt
        domains_in_txt = re.findall(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', txt)
        for dom in domains_in_txt:
            if valid(dom) and dom != d:
                found.add(dom)
                edges.append((d, dom, 'TXT'))
    
    # srv - services
    for item in SRV:
        svc = item[0]
        proto = item[1]
        srv_name = '_' + svc + '._' + proto + '.' + d
        srv_records = query(srv_name, 'SRV')
        for srv in srv_records:
            parts = srv.split()
            if len(parts) >= 4:
                h = parts[3].rstrip('.')
                if valid(h):
                    found.add(h)
                    edges.append((d, h, 'SRV'))
    
    # A records + reverse dns + ip neighbors
    a_records = query(d, 'A')
    for ip in a_records:
        # reverse dns
        rev = reverse_dns(ip)
        if rev and valid(rev) and rev != d:
            found.add(rev)
            edges.append((d, rev, 'PTR'))
        
        # ip neighbors - check ips autour
        parts = ip.split('.')
        if len(parts) == 4:
            base = parts[0] + '.' + parts[1] + '.' + parts[2] + '.'
            last = int(parts[3])
            # check ip-1 et ip+1
            for neighbor in [last - 1, last + 1]:
                if neighbor >= 0 and neighbor <= 255:
                    neighbor_ip = base + str(neighbor)
                    rev = reverse_dns(neighbor_ip)
                    if rev and valid(rev) and rev != d:
                        found.add(rev)
                        edges.append((d, rev, 'NEIGHBOR'))
    
    # sous domaines
    if check_subs:
        for sub in SUBS:
            sd = sub + '.' + d
            a_records = query(sd, 'A')
            if len(a_records) > 0:
                found.add(sd)
                edges.append((d, sd, 'SUB'))
    
    # domaine parent (crawl to TLD)
    parts = d.split('.')
    if len(parts) > 2:
        # trouve tous les parents jusqu'au TLD
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent not in TLDS and len(parent) > 4:
                found.add(parent)
                edges.append((d, parent, 'PARENT'))
                break  # juste le premier parent
    
    return found, edges
