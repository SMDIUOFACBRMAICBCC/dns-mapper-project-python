# scan recursif
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns_query import scan_one, valid


def scan(target, depth):
    # scan le domaine et les domaines lié
    domains = set()
    domains.add(target)
    edges = []
    visited = set()
    queue = set()
    queue.add(target)
    
    for lvl in range(depth):
        # si queue vide on arrete
        if len(queue) == 0:
            break
        
        # filtre les domaines pas encore visité
        todo = []
        for d in queue:
            if d not in visited:
                if valid(d):
                    todo.append(d)
        
        if len(todo) == 0:
            break
        
        # sous domaines seulement niveau 0 et 1
        check_subs = False
        if lvl < 2:
            check_subs = True
        
        # affiche progression
        msg = "[" + str(lvl+1) + "/" + str(depth) + "] " + str(len(todo)) + " domains"
        if check_subs:
            msg = msg + " +subs"
        print(msg + "...")
        
        # lance les threads
        pool = ThreadPoolExecutor(max_workers=25)
        futures = {}
        for d in todo:
            f = pool.submit(scan_one, d, check_subs)
            futures[f] = d
        
        next_queue = set()
        
        # recup resultats
        for f in as_completed(futures):
            d = futures[f]
            visited.add(d)
            try:
                result = f.result()
                doms = result[0]
                edg = result[1]
                for dom in doms:
                    if valid(dom):
                        domains.add(dom)
                for e in edg:
                    edges.append(e)
                for dom in doms:
                    next_queue.add(dom)
            except:
                pass
        
        pool.shutdown()
        
        # update queue
        queue = set()
        for d in next_queue:
            if d not in visited:
                queue.add(d)
    
    return domains, edges
