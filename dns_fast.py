#!/usr/bin/env python3
# dns mapper
import sys
import os
import subprocess
import shutil
from dns_scanner import scan
from results_generator import generate_results
from graph_style import make_dot

# cherche dot dans le PATH
GRAPHVIZ = shutil.which('dot')


if __name__ == '__main__':
    # aide
    if len(sys.argv) < 2:
        print("DNS Mapper")
        print("")
        print("Usage: python dns_fast.py <domain> <depth> <output>")
        print("")
        print("Output: --results --graph --dot --all")
        print("")
        print("Ex: python dns_fast.py example.com 5 --graph")
        sys.exit(0)
    
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        print("DNS Mapper")
        print("")
        print("Usage: python dns_fast.py <domain> <depth> <output>")
        print("")
        print("Output: --results --graph --dot --all")
        print("")
        print("Ex: python dns_fast.py example.com 5 --graph")
        sys.exit(0)
    
    # parse args
    target = sys.argv[1].lower()
    target = target.rstrip('.')
    
    # trouve depth
    depth = None
    for arg in sys.argv[2:]:
        if arg.isdigit():
            depth = int(arg)
            break
    
    # options
    args = sys.argv[2:]
    results = False
    graph = False
    dot = False
    
    if '--results' in args or '--all' in args:
        results = True
    if '--graph' in args or '--all' in args:
        graph = True
    if '--dot' in args or '--all' in args:
        dot = True
    
    # verif depth
    if depth is None:
        print("Erreur: profondeur requise")
        sys.exit(1)
    
    # max 7
    if depth > 7:
        print("Note: max 7 (demandé " + str(depth) + ")")
        depth = 7
    
    # verif output
    if not results and not graph and not dot:
        print("Erreur: output requis (--results/--graph/--dot/--all)")
        sys.exit(1)
    
    # lance scan
    print("")
    print("=== DNS Mapper: " + target + " (depth=" + str(depth) + ") ===")
    print("")
    
    result = scan(target, depth)
    domains = result[0]
    edges = result[1]
    
    print("")
    print("=== " + str(len(domains)) + " domaines trouvé ===")
    print("")
    
    # results.txt
    if results:
        content = generate_results(target, domains, edges)
        f = open('Results.txt', 'w', encoding='utf-8')
        f.write(content)
        f.close()
        print("Saved: Results.txt")
    
    # graph.dot
    if dot or graph:
        content = make_dot(target, domains, edges)
        f = open('graph.dot', 'w', encoding='utf-8')
        f.write(content)
        f.close()
        if dot:
            print("Saved: graph.dot")
    
    # graph.png
    if graph:
        if GRAPHVIZ:
            if len(domains) > 200:
                dpi = 200
            else:
                dpi = 150
            
            cmd = [GRAPHVIZ, '-Tpng', '-Gdpi=' + str(dpi), 'graph.dot', '-o', 'graph.png']
            subprocess.run(cmd, capture_output=True)
            print("Saved: graph.png")
        else:
            print("Graphviz pas trouvé. Installe depuis: https://graphviz.org/download/")
