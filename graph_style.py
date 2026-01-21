# genere le graphe dot

# couleurs par niveau
COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6', 
          '#3b82f6', '#8b5cf6', '#ec4899', '#6b7280']

# couleurs des fleches
EDGE_COLORS = {
    'MX': '#f87171',
    'NS': '#60a5fa',
    'SOA': '#a78bfa',
    'CNAME': '#2dd4bf',
    'SPF': '#fb923c',
    'SRV': '#f472b6',
    'SUB': '#4ade80',
    'PARENT': '#6b7280',
    'PTR': '#fbbf24',
    'TXT': '#a3e635',
    'NEIGHBOR': '#94a3b8'
}


def valid(d):
    if not d:
        return False
    if len(d) >= 254:
        return False
    if '.' not in d:
        return False
    for c in '%{}" \n\r\t':
        if c in d:
            return False
    return True


def escape(s):
    s = s.replace('\\', '')
    s = s.replace('"', '')
    s = s.replace('\n', '')
    return s


def make_dot(target, domains, edges, max_edges=400):
    # genere le code dot
    
    # filtre domaines valides
    valid_domains = set()
    for d in domains:
        if valid(d):
            valid_domains.add(d)
    
    n = len(valid_domains)
    
    # params selon taille
    if n > 300:
        sep = 0.8
        nsep = 0.05
        fs = 7
        h = 0.18
        m = '0.04,0.02'
        mpl = 50
    elif n > 150:
        sep = 1.0
        nsep = 0.08
        fs = 8
        h = 0.22
        m = '0.06,0.03'
        mpl = 80
    elif n > 80:
        sep = 1.2
        nsep = 0.12
        fs = 9
        h = 0.26
        m = '0.08,0.04'
        mpl = 120
    else:
        sep = 1.5
        nsep = 0.20
        fs = 10
        h = 0.32
        m = '0.10,0.05'
        mpl = 200
    
    # bfs pour calculer les layers
    layers = {}
    layers[target] = 0
    queue = [target]
    
    # construit la map des edges
    edge_map = {}
    for e in edges:
        s = e[0]
        t = e[1]
        if s not in edge_map:
            edge_map[s] = []
        edge_map[s].append(t)
    
    # bfs
    while len(queue) > 0:
        cur = queue.pop(0)
        if cur in edge_map:
            for t in edge_map[cur]:
                if t in valid_domains:
                    if t not in layers:
                        layers[t] = layers[cur] + 1
                        queue.append(t)
    
    # groupe par layer
    layer_groups = {}
    for d in layers:
        l = layers[d]
        if l not in layer_groups:
            layer_groups[l] = []
        layer_groups[l].append(d)
    
    # construit le dot
    lines = []
    lines.append('digraph G {')
    lines.append('')
    lines.append('  bgcolor="#16162a"')
    lines.append('  rankdir=LR')
    lines.append('  ranksep=' + str(sep))
    lines.append('  nodesep=' + str(nsep))
    lines.append('  splines=polyline')
    lines.append('  overlap=false')
    lines.append('')
    lines.append('  node [shape=box style="filled,rounded" fontname="Consolas" fontsize=' + str(fs))
    lines.append('        fontcolor="white" height=' + str(h) + ' margin="' + m + '"]')
    lines.append('')
    lines.append('  edge [penwidth=0.5 arrowsize=0.3]')
    lines.append('')
    
    # ajoute les nodes par layer
    shown = set()
    layer_nums = sorted(layer_groups.keys())
    
    for l in layer_nums:
        if l > 7:
            continue
        
        doms = layer_groups[l]
        doms = sorted(doms)
        doms = doms[:mpl]
        
        if l < len(COLORS):
            c = COLORS[l]
        else:
            c = COLORS[-1]
        
        lines.append('  // layer ' + str(l))
        lines.append('  { rank=same')
        
        for d in doms:
            shown.add(d)
            lines.append('    "' + escape(d) + '" [fillcolor="' + c + '"]')
        
        lines.append('  }')
        lines.append('')
    
    # ajoute les edges
    lines.append('  // edges')
    seen = set()
    cnt = 0
    
    for e in edges:
        if cnt >= max_edges:
            break
        
        s = e[0]
        t = e[1]
        r = e[2]
        
        if s in shown and t in shown:
            if (s, t) not in seen:
                sl = layers.get(s, 99)
                tl = layers.get(t, 99)
                
                if sl < tl and tl <= sl + 2:
                    if r in EDGE_COLORS:
                        color = EDGE_COLORS[r]
                    else:
                        color = '#6b7280'
                    
                    lines.append('  "' + escape(s) + '"->"' + escape(t) + '" [color="' + color + '"]')
                    seen.add((s, t))
                    cnt = cnt + 1
    
    lines.append('}')
    
    result = '\n'.join(lines)
    return result
