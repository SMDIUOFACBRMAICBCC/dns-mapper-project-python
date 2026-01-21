#!/usr/bin/env python3
# dns mapper - scan un domaine et fait un graphe
import sys
import subprocess
import shutil
from dns_scanner import scan
from results_generator import generate_results
from graph_style import make_dot

# on cherche graphviz
GRAPHVIZ = shutil.which('dot')


if __name__ == '__main__':
    # aide
    if len(sys.argv) < 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
        print("DNS Mapper")
        print("")
        print("Usage: python dns_fast.py <domain> <depth> <output>")
        print("")
        print("Output: --results --graph --dot --all")
        print("")
        print("Ex: python dns_fast.py example.com 5 --graph")
        sys.exit(0)
    
    # recupere le domaine
    target = sys.argv[1].lower().rstrip('.')
    
    # trouve depth
    depth = None
    for arg in sys.argv[2:]:
        if arg.isdigit():
            depth = int(arg)
            break
    
    if depth is None:
        print("Erreur: profondeur requise")
        sys.exit(1)
    
    # max 7 niveaux
    if depth > 7:
        print("Note: max 7 (demandé " + str(depth) + ")")
        depth = 7
    
    # options de sortie
    args = sys.argv[2:]
    results = '--results' in args or '--all' in args
    graph = '--graph' in args or '--all' in args
    dot = '--dot' in args or '--all' in args
    
    if not results and not graph and not dot:
        print("Erreur: output requis (--results/--graph/--dot/--all)")
        sys.exit(1)
    
    # lance le scan
    print("")
    print("=== DNS Mapper: " + target + " (depth=" + str(depth) + ") ===")
    print("")
    
    result = scan(target, depth)
    domains = result[0]
    edges = result[1]
    
    print("")
    print("=== " + str(len(domains)) + " domaines trouvé ===")
    print("")
    
    # sauvegarde results.txt
    if results:
        content = generate_results(target, domains, edges)
        f = open('Results.txt', 'w', encoding='utf-8')
        f.write(content)
        f.close()
        print("Saved: Results.txt")
    
    # sauvegarde graph.dot
    if dot or graph:
        content = make_dot(target, domains, edges)
        f = open('graph.dot', 'w', encoding='utf-8')
        f.write(content)
        f.close()
        if dot:
            print("Saved: graph.dot")
    
    # genere graph.png et graph.svg
    if graph:
        if GRAPHVIZ:
            # dpi selon nb de domaines
            if len(domains) > 500:
                dpi = 300
            elif len(domains) > 200:
                dpi = 250
            else:
                dpi = 200
            
            # png
            cmd = [GRAPHVIZ, '-Tpng', '-Gdpi=' + str(dpi), 'graph.dot', '-o', 'graph.png']
            subprocess.run(cmd, capture_output=True)
            print("Saved: graph.png")
            
            # svg pour zoom
            cmd = [GRAPHVIZ, '-Tsvg', 'graph.dot', '-o', 'graph.svg']
            subprocess.run(cmd, capture_output=True)
            print("Saved: graph.svg")
        else:
            print("Graphviz pas trouvé. Installe: https://graphviz.org/download/")
