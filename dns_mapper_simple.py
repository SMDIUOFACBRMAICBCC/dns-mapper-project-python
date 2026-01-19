#!/usr/bin/env python3
"""
DNS Mapper - Simple Version
Cartographie l'environnement DNS d'un domaine.

Auteur: [Ton nom]
Cours: Python B1 - OTERIA 2025-2026
"""

import sys
import dns.resolver
import dns.reversename

# ============================================================
# CONFIGURATION
# ============================================================

# Sous-domaines courants à tester
SUBDOMAINS = ['www', 'mail', 'api', 'admin', 'ftp', 'dev', 'test', 'staging', 
              'blog', 'shop', 'app', 'portal', 'cdn', 'vpn', 'remote']

# Services SRV à scanner
SRV_SERVICES = [
    ('sip', 'tcp'),      # VoIP
    ('xmpp-server', 'tcp'),  # Messagerie
    ('ldap', 'tcp'),     # Annuaire
]


# ============================================================
# FONCTIONS DNS
# ============================================================

def dns_query(domain: str, record_type: str) -> list:
    """Effectue une requête DNS et retourne les résultats."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=3)
        return [str(rdata) for rdata in answers]
    except:
        return []


def reverse_dns(ip: str) -> str:
    """Résolution inverse: IP -> nom de domaine."""
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, 'PTR', lifetime=3)
        return str(list(answers)[0]).rstrip('.')
    except:
        return None


# ============================================================
# STRATEGIES DE DECOUVERTE
# ============================================================

def strategy_basic_records(domain: str) -> dict:
    """Stratégie 1: Récupérer les enregistrements de base (A, AAAA, MX, NS)."""
    print(f"  [1] Enregistrements de base pour {domain}...")
    
    results = {'domains': set(), 'ips': set(), 'edges': []}
    
    # Enregistrements A (IPv4)
    for ip in dns_query(domain, 'A'):
        results['ips'].add(ip)
        results['edges'].append((domain, ip, 'A'))
    
    # Enregistrements MX (serveurs mail)
    for mx in dns_query(domain, 'MX'):
        mx_domain = mx.split()[-1].rstrip('.')
        results['domains'].add(mx_domain)
        results['edges'].append((domain, mx_domain, 'MX'))
    
    # Enregistrements NS (serveurs DNS)
    for ns in dns_query(domain, 'NS'):
        ns_domain = ns.rstrip('.')
        results['domains'].add(ns_domain)
        results['edges'].append((domain, ns_domain, 'NS'))
    
    return results


def strategy_reverse_dns(ips: set) -> dict:
    """Stratégie 2: Résolution inverse des IPs."""
    print(f"  [2] Reverse DNS pour {len(ips)} IPs...")
    
    results = {'domains': set(), 'ips': set(), 'edges': []}
    
    for ip in ips:
        ptr = reverse_dns(ip)
        if ptr:
            results['domains'].add(ptr)
            results['edges'].append((ip, ptr, 'PTR'))
    
    return results


def strategy_subdomains(domain: str) -> dict:
    """Stratégie 3: Énumération des sous-domaines courants."""
    print(f"  [3] Énumération des sous-domaines...")
    
    results = {'domains': set(), 'ips': set(), 'edges': []}
    
    for sub in SUBDOMAINS:
        subdomain = f"{sub}.{domain}"
        ips = dns_query(subdomain, 'A')
        
        if ips:
            results['domains'].add(subdomain)
            results['edges'].append((domain, subdomain, 'SUBDOMAIN'))
            
            for ip in ips:
                results['ips'].add(ip)
                results['edges'].append((subdomain, ip, 'A'))
    
    return results


def strategy_srv(domain: str) -> dict:
    """Stratégie 4: Scan des enregistrements SRV."""
    print(f"  [4] Scan SRV...")
    
    results = {'domains': set(), 'ips': set(), 'edges': []}
    
    for service, proto in SRV_SERVICES:
        srv_domain = f"_{service}._{proto}.{domain}"
        records = dns_query(srv_domain, 'SRV')
        
        for record in records:
            parts = record.split()
            if len(parts) >= 4:
                target = parts[3].rstrip('.')
                results['domains'].add(target)
                results['edges'].append((domain, target, f'SRV/{service}'))
    
    return results


def strategy_txt(domain: str) -> dict:
    """Stratégie 5: Parser les TXT (SPF, DMARC)."""
    print(f"  [5] Analyse TXT/SPF/DMARC...")
    
    results = {'domains': set(), 'ips': set(), 'edges': []}
    
    # TXT records
    for txt in dns_query(domain, 'TXT') + dns_query(f'_dmarc.{domain}', 'TXT'):
        # Extraire les domaines (include:, redirect=, etc.)
        import re
        domains_found = re.findall(r'include:([^\s]+)', txt)
        domains_found += re.findall(r'redirect=([^\s]+)', txt)
        
        for d in domains_found:
            d = d.rstrip('.')
            results['domains'].add(d)
            results['edges'].append((domain, d, 'TXT/SPF'))
    
    return results


# ============================================================
# GENERATION DU GRAPHE (GRAPHVIZ)
# ============================================================

def generate_dot(domain: str, all_domains: set, all_ips: set, edges: list) -> str:
    """Génère le code DOT pour Graphviz."""
    
    lines = ['digraph "DNS Map" {']
    lines.append('  // Style')
    lines.append('  bgcolor="#1a1a2e"')
    lines.append('  node [style=filled, fontcolor=white, fontname=Arial]')
    lines.append('  edge [fontcolor="#cccccc", fontname=Arial, fontsize=9]')
    lines.append('')
    
    # Noeud principal (rouge)
    lines.append(f'  // Domaine principal')
    lines.append(f'  "{domain}" [fillcolor="#FF6B6B", shape=box]')
    lines.append('')
    
    # Domaines (bleu)
    lines.append('  // Domaines découverts')
    for d in all_domains:
        if d != domain:
            lines.append(f'  "{d}" [fillcolor="#4A90D9", shape=box]')
    lines.append('')
    
    # IPs (vert)
    lines.append('  // Adresses IP')
    for ip in all_ips:
        lines.append(f'  "{ip}" [fillcolor="#50C878", shape=ellipse]')
    lines.append('')
    
    # Arêtes
    lines.append('  // Relations')
    seen_edges = set()
    for src, dst, label in edges:
        edge_key = (src, dst)
        if edge_key not in seen_edges:
            lines.append(f'  "{src}" -> "{dst}" [label="{label}"]')
            seen_edges.add(edge_key)
    
    lines.append('}')
    return '\n'.join(lines)


def generate_text_report(domain: str, domains: set, ips: set, edges: list) -> str:
    """Génère un rapport textuel."""
    
    lines = [f"=== Rapport DNS pour {domain} ===", ""]
    
    lines.append("DOMAINES DÉCOUVERTS:")
    for d in sorted(domains):
        lines.append(f"  - {d}")
    
    lines.append("")
    lines.append("ADRESSES IP:")
    for ip in sorted(ips):
        ptr = reverse_dns(ip)
        if ptr:
            lines.append(f"  - {ip} -> {ptr}")
        else:
            lines.append(f"  - {ip}")
    
    lines.append("")
    lines.append(f"Total: {len(domains)} domaines, {len(ips)} IPs")
    
    return '\n'.join(lines)


# ============================================================
# FONCTION PRINCIPALE
# ============================================================

def main():
    """Point d'entrée principal."""
    
    # Vérifier les arguments
    if len(sys.argv) < 2:
        print("Usage: python dns_mapper_simple.py <domaine> [--dot fichier.dot]")
        print("Exemple: python dns_mapper_simple.py example.com")
        print("         python dns_mapper_simple.py example.com --dot graph.dot")
        sys.exit(1)
    
    domain = sys.argv[1].lower().rstrip('.')
    output_dot = None
    
    # Option --dot
    if '--dot' in sys.argv:
        idx = sys.argv.index('--dot')
        if idx + 1 < len(sys.argv):
            output_dot = sys.argv[idx + 1]
    
    print(f"\n{'='*50}")
    print(f"DNS Mapper - Analyse de {domain}")
    print(f"{'='*50}\n")
    
    # Collections pour stocker les résultats
    all_domains = {domain}
    all_ips = set()
    all_edges = []
    
    # Exécuter les stratégies
    strategies = [
        strategy_basic_records,
        strategy_subdomains,
        strategy_srv,
        strategy_txt,
    ]
    
    for strategy in strategies:
        try:
            result = strategy(domain)
            all_domains.update(result['domains'])
            all_ips.update(result['ips'])
            all_edges.extend(result['edges'])
        except Exception as e:
            print(f"    Erreur: {e}")
    
    # Reverse DNS sur les IPs trouvées
    result = strategy_reverse_dns(all_ips)
    all_domains.update(result['domains'])
    all_edges.extend(result['edges'])
    
    print(f"\n{'='*50}")
    print(f"Découverte terminée!")
    print(f"  - {len(all_domains)} domaines")
    print(f"  - {len(all_ips)} adresses IP")
    print(f"{'='*50}\n")
    
    # Afficher le rapport textuel
    print(generate_text_report(domain, all_domains, all_ips, all_edges))
    
    # Sauvegarder le DOT si demandé
    if output_dot:
        dot_content = generate_dot(domain, all_domains, all_ips, all_edges)
        with open(output_dot, 'w', encoding='utf-8') as f:
            f.write(dot_content)
        print(f"\nGraphe sauvegardé: {output_dot}")
        print(f"Pour générer l'image: dot -Tpng {output_dot} -o graph.png")


if __name__ == '__main__':
    main()
