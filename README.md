# DNS Mapper

Outil pour scanner l'infrastructure DNS d'un domaine.

## Installation

```
pip install dnspython
```

Il faut aussi Graphviz pour les images:
https://graphviz.org/download/

## Utilisation

```
python dns_fast.py <domaine> <profondeur> <sortie>
```

Sorties possibles:
- `--results` - fichier Results.txt
- `--graph` - image graph.png
- `--dot` - fichier graph.dot
- `--all` - tout

## Exemples

```
python dns_fast.py example.com 5 --graph
python dns_fast.py example.com 5 --all
python dns_fast.py example.com 3 --results
```

## Fichiers

- `dns_fast.py` - programme principal
- `dns_query.py` - requetes dns
- `dns_scanner.py` - scan recursif
- `dns_config.py` - config
- `graph_style.py` - generation graphe
- `results_generator.py` - generation results.txt
