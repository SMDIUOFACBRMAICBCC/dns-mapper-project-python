# genere results.txt
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns_query import query


def get_info(d):
    # recup info basique
    return {
        'domain': d,
        'ips': query(d, 'A'),
        'mx': query(d, 'MX'),
        'ns': query(d, 'NS')
    }


def generate_results(target, domains, edges):
    # genere le contenu du fichier
    out = []
    
    out.append("# DNS MAP: " + target)
    out.append("# Domains: " + str(len(domains)))
    out.append("# Edges: " + str(len(edges)))
    out.append("")
    
    # stats
    stats = {}
    for e in edges:
        r = e[2]
        stats[r] = stats.get(r, 0) + 1
    
    out.append("# STATS")
    for r, c in sorted(stats.items(), key=lambda x: -x[1]):
        out.append("  " + r + ": " + str(c))
    out.append("")
    
    # recup infos dns
    print("Collecting domain info...")
    sorted_doms = sorted(domains)[:100]
    
    pool = ThreadPoolExecutor(max_workers=20)
    futures = {pool.submit(get_info, d): d for d in sorted_doms}
    
    infos = {}
    for f in as_completed(futures):
        try:
            i = f.result()
            infos[i['domain']] = i
        except:
            pass
    pool.shutdown()
    
    # liste domaines
    out.append("# DOMAINS")
    out.append("")
    
    for d in sorted(domains):
        out.append("[" + d + "]")
        
        if d in infos:
            i = infos[d]
            if i['ips']:
                out.append("  A: " + ', '.join(i['ips']))
            if i['mx']:
                out.append("  MX: " + ', '.join(i['mx']))
            if i['ns']:
                out.append("  NS: " + ', '.join(i['ns']))
        
        # liens
        liens = [(e[1], e[2]) for e in edges if e[0] == d][:5]
        if liens:
            out.append("  -> " + ', '.join([l[0] + '(' + l[1] + ')' for l in liens]))
        
        out.append("")
    
    return "\n".join(out)
