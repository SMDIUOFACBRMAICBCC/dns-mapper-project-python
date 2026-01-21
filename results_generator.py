# genere results.txt
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns_query import query


def get_info(d):
    # recup info dns
    info = {}
    info['domain'] = d
    info['ips'] = query(d, 'A')
    info['mx'] = query(d, 'MX')
    info['ns'] = query(d, 'NS')
    return info


def generate_results(target, domains, edges):
    # genere le fichier results
    lines = []
    
    # header
    lines.append("# DNS MAP: " + target)
    lines.append("# Domains: " + str(len(domains)))
    lines.append("# Edges: " + str(len(edges)))
    lines.append("")
    
    # calcul stats
    stats = {}
    for e in edges:
        r = e[2]
        if r in stats:
            stats[r] = stats[r] + 1
        else:
            stats[r] = 1
    
    lines.append("# STATS")
    
    # trie par count
    stats_list = []
    for r in stats:
        stats_list.append((r, stats[r]))
    stats_list.sort(key=lambda x: x[1], reverse=True)
    
    for item in stats_list:
        lines.append("  " + item[0] + ": " + str(item[1]))
    lines.append("")
    
    # recup infos
    print("Collecting domain info...")
    sorted_domains = sorted(domains)
    infos = {}
    
    # limite a 100
    domains_to_check = sorted_domains[:100]
    
    pool = ThreadPoolExecutor(max_workers=20)
    futures = {}
    for d in domains_to_check:
        f = pool.submit(get_info, d)
        futures[f] = d
    
    for f in as_completed(futures):
        try:
            i = f.result()
            infos[i['domain']] = i
        except:
            pass
    
    pool.shutdown()
    
    lines.append("# DOMAINS")
    lines.append("")
    
    for d in sorted_domains:
        lines.append("[" + d + "]")
        
        if d in infos:
            i = infos[d]
            if len(i['ips']) > 0:
                lines.append("  A: " + ', '.join(i['ips']))
            if len(i['mx']) > 0:
                lines.append("  MX: " + ', '.join(i['mx']))
            if len(i['ns']) > 0:
                lines.append("  NS: " + ', '.join(i['ns']))
        
        # edges sortantes
        out = []
        for e in edges:
            if e[0] == d:
                out.append((e[1], e[2]))
        out = out[:5]
        
        if len(out) > 0:
            parts = []
            for item in out:
                parts.append(item[0] + '(' + item[1] + ')')
            lines.append("  ->: " + ', '.join(parts))
        
        lines.append("")
    
    return "\n".join(lines)
