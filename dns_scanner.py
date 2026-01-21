# scan recursif des domaines
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns_query import scan_one, valid


def scan(target, depth):
    # scan le domaine cible et tout ce qu'on trouve
    domains = set()
    domains.add(target)
    edges = []
    visited = set()
    queue = set()
    queue.add(target)
    
    for lvl in range(depth):
        if len(queue) == 0:
            break
        
        # domaines a scanner
        todo = []
        for d in queue:
            if d not in visited and valid(d):
                todo.append(d)
        
        if len(todo) == 0:
            break
        
        # sous domaines niveau 0-1 seulement
        check_subs = lvl < 2
        
        # progress
        msg = "[" + str(lvl+1) + "/" + str(depth) + "] " + str(len(todo)) + " domains"
        if check_subs:
            msg = msg + " +subs"
        print(msg + "...")
        
        # lance threads
        pool = ThreadPoolExecutor(max_workers=25)
        futures = {}
        for d in todo:
            futures[pool.submit(scan_one, d, check_subs)] = d
        
        next_queue = set()
        
        # resultats
        for f in as_completed(futures):
            d = futures[f]
            visited.add(d)
            try:
                doms, edg = f.result()
                for dom in doms:
                    if valid(dom):
                        domains.add(dom)
                        next_queue.add(dom)
                edges.extend(edg)
            except:
                pass
        
        pool.shutdown()
        
        # prochaine iteration
        queue = set()
        for d in next_queue:
            if d not in visited:
                queue.add(d)
    
    return domains, edges
