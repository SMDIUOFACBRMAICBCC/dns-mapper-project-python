# graphe dns - genere le fichier dot
# fait le 21/01

COULEURS = [
    '#dc2626', '#ea580c', '#d97706', '#65a30d',
    '#16a34a', '#0891b2', '#2563eb', '#7c3aed'
]

COULEURS_FLECHES = {
    'MX': '#f87171', 'NS': '#60a5fa', 'SOA': '#a78bfa',
    'CNAME': '#2dd4bf', 'SPF': '#fb923c', 'SRV': '#f472b6',
    'SUB': '#4ade80', 'PARENT': '#a1a1aa', 'PTR': '#fbbf24',
    'TXT': '#a3e635', 'NEIGHBOR': '#94a3b8'
}


def valide(d):
    # check si domaine est ok
    if not d or len(d) >= 254 or '.' not in d:
        return False
    for c in '%{}" \n\r\t':
        if c in d:
            return False
    return True


def echap(s):
    # escape les guillemets
    return s.replace('"', '\\"').replace('\\', '\\\\')


def make_dot(target, domains, edges):
    # genere le contenu dot pour graphviz
    
    # filtre domaines valide
    ok = set()
    for d in domains:
        if valide(d):
            ok.add(d)
    
    # map des edges
    enfants = {}
    parents = {}
    for e in edges:
        s = e[0]
        t = e[1]
        if s not in enfants:
            enfants[s] = []
        enfants[s].append(t)
        if t not in parents:
            parents[t] = []
        parents[t].append(s)
    
    # bfs pour trouver les layers
    layers = {target: 0}
    queue = [target]
    while queue:
        cur = queue.pop(0)
        if cur in enfants:
            for t in enfants[cur]:
                if t in ok and t not in layers:
                    layers[t] = layers[cur] + 1
                    queue.append(t)
    
    # groupe par layer
    groupes = {}
    for d in layers:
        l = layers[d]
        if l not in groupes:
            groupes[l] = []
        groupes[l].append(d)
    
    # selection greedy - on prend les plus connecte
    visible = set()
    visible.add(target)
    
    limites = {0: 1, 1: 40, 2: 35, 3: 30, 4: 25, 5: 20, 6: 15, 7: 12}
    
    for l in range(1, 8):
        if l not in groupes:
            continue
        
        candidats = groupes[l]
        limite = limites.get(l, 10)
        
        # score par nb de parents visible
        scores = []
        for d in candidats:
            ps = parents.get(d, [])
            nb = 0
            for p in ps:
                if p in visible and layers.get(p, 999) < l:
                    nb = nb + 1
            if nb > 0:
                scores.append((d, nb))
        
        # trie par score desc
        scores.sort(key=lambda x: -x[1])
        
        # prend les top
        for item in scores[:limite]:
            visible.add(item[0])
    
    # construit le dot
    out = []
    out.append('digraph DNS {')
    out.append('  bgcolor="#0f172a"')
    out.append('  rankdir=TB')
    out.append('  ranksep=0.8')
    out.append('  nodesep=0.25')
    out.append('  splines=true')
    out.append('')
    out.append('  node [shape=box style="filled,rounded" fontname="Segoe UI" fontsize=9')
    out.append('        fontcolor="white" penwidth=0 height=0.3 margin="0.1,0.05"]')
    out.append('')
    out.append('  edge [penwidth=1.0 arrowsize=0.4 color="#475569"]')
    out.append('')
    
    # nodes par layer
    for l in sorted(groupes.keys()):
        if l > 7:
            break
        
        nodes = []
        for d in groupes[l]:
            if d in visible:
                nodes.append(d)
        
        if len(nodes) == 0:
            continue
        
        couleur = COULEURS[l] if l < len(COULEURS) else COULEURS[-1]
        
        out.append('  // layer ' + str(l))
        out.append('  { rank=same')
        
        for d in sorted(nodes):
            if len(d) < 30:
                label = d
            else:
                label = d[:27] + '...'
            out.append('    "' + echap(d) + '" [label="' + echap(label) + '" fillcolor="' + couleur + '"]')
        
        out.append('  }')
    
    # edges - seulement vers l'avant
    out.append('')
    out.append('  // fleches')
    deja = set()
    
    for e in edges:
        s = e[0]
        t = e[1]
        if len(e) > 2:
            rtype = e[2]
        else:
            rtype = 'DEFAULT'
        
        if s in visible and t in visible:
            ls = layers.get(s, 999)
            lt = layers.get(t, 999)
            
            if ls < lt:
                cle = s + '->' + t
                if cle not in deja:
                    couleur = COULEURS_FLECHES.get(rtype, '#64748b')
                    out.append('  "' + echap(s) + '" -> "' + echap(t) + '" [color="' + couleur + '"]')
                    deja.add(cle)
    
    out.append('}')
    return '\n'.join(out)
