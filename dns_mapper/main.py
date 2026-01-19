"""DNS Mapper - Main entry point and CLI interface."""

import argparse
import sys
from typing import Set, Dict, List, Tuple

from .resolver import DNSResolver
from .strategies import (
    ALL_STRATEGIES,
    DiscoveryResult,
    ParseTXTStrategy,
    CrawlTLDStrategy,
    ScanSRVStrategy,
    ReverseDNSStrategy,
    IPNeighborsStrategy,
    SubdomainStrategy
)
from .graph import create_graph
from .utils import is_valid_domain


class DNSMapper:
    """Main DNS Mapper class for orchestrating discovery."""
    
    def __init__(self, target: str, depth: int = 2, 
                 strategies: List[str] = None, verbose: bool = True):
        """Initialize the DNS Mapper.
        
        Args:
            target: Target domain to analyze
            depth: Maximum recursion depth
            strategies: List of strategy names to use (None = all)
            verbose: Print progress messages
        """
        self.target = target.lower().rstrip('.')
        self.depth = depth
        self.verbose = verbose
        self.resolver = DNSResolver()
        
        # Initialize selected strategies
        strategy_names = strategies or list(ALL_STRATEGIES.keys())
        self.strategies = []
        for name in strategy_names:
            if name in ALL_STRATEGIES:
                strategy_class = ALL_STRATEGIES[name]
                if name == 'ip_neighbors':
                    self.strategies.append(strategy_class(self.resolver, neighbor_range=3))
                else:
                    self.strategies.append(strategy_class(self.resolver))
        
        # Results
        self.result = DiscoveryResult()
        self.visited_domains: Set[str] = set()
        self.visited_ips: Set[str] = set()
    
    def _log(self, message: str) -> None:
        """Print message if verbose mode is on."""
        if self.verbose:
            print(message, file=sys.stderr)
    
    def run(self) -> DiscoveryResult:
        """Run the DNS mapping.
        
        Returns:
            DiscoveryResult with all discoveries
        """
        self._log(f"Starting DNS mapping for: {self.target}")
        self._log(f"Depth: {self.depth}")
        self._log(f"Strategies: {[s.name for s in self.strategies]}")
        self._log("-" * 50)
        
        # Add target to results
        self.result.domains[self.target] = [('TARGET', 'initial')]
        
        # Get initial IPs for target
        a_records = self.resolver.query_a(self.target)
        for ip in a_records:
            self.result.add_ip(ip, 'A', self.target)
        
        # Run discovery with depth control
        domains_to_explore = {self.target}
        
        for current_depth in range(self.depth):
            self._log(f"\n=== Depth {current_depth + 1}/{self.depth} ===")
            
            new_domains: Set[str] = set()
            
            for domain in domains_to_explore:
                if domain in self.visited_domains:
                    continue
                
                self.visited_domains.add(domain)
                self._log(f"  Exploring: {domain}")
                
                # Run all strategies on this domain
                for strategy in self.strategies:
                    try:
                        strategy_result = strategy.execute(domain)
                        self.result.merge(strategy_result)
                        new_domains.update(strategy_result.get_all_domains())
                    except Exception as e:
                        self._log(f"    Error in {strategy.name}: {e}")
            
            # Filter out already visited domains
            domains_to_explore = new_domains - self.visited_domains
            
            if not domains_to_explore:
                self._log("  No new domains to explore")
                break
            
            self._log(f"  Found {len(domains_to_explore)} new domains")
        
        self._log("\n" + "=" * 50)
        self._log(f"Discovery complete!")
        self._log(f"Total domains: {len(self.result.domains)}")
        self._log(f"Total IPs: {len(self.result.ips)}")
        
        return self.result
    
    def get_text_report(self) -> str:
        """Generate a text report of the results.
        
        Returns:
            Formatted text report
        """
        lines = []
        lines.append(f"=== DNS Mapper Report for {self.target} ===\n")
        
        # Domains section
        lines.append("DOMAINS DISCOVERED:")
        lines.append("-" * 40)
        for domain in sorted(self.result.domains.keys()):
            records = self.result.domains[domain]
            record_types = list(set(r[0] for r in records))
            lines.append(f"  {domain}")
            lines.append(f"    Records: {', '.join(record_types)}")
        
        lines.append("")
        
        # IPs section
        lines.append("IP ADDRESSES DISCOVERED:")
        lines.append("-" * 40)
        for ip in sorted(self.result.ips.keys()):
            records = self.result.ips[ip]
            sources = list(set(r[1] for r in records))
            lines.append(f"  {ip}")
            lines.append(f"    Sources: {', '.join(sources[:3])}")
        
        lines.append("")
        lines.append(f"Total: {len(self.result.domains)} domains, {len(self.result.ips)} IPs")
        
        return '\n'.join(lines)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='dns_mapper',
        description='Map DNS environment of a domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python -m dns_mapper example.com
  python -m dns_mapper example.com -d 2 -f png -o graph.png
  python -m dns_mapper example.com -f svg -o graph
  python -m dns_mapper example.com -s parse_txt,subdomain

Strategies:
  parse_txt    - Parse TXT records for domains and IPs
  crawl_tld    - Discover parent domains up to TLD
  scan_srv     - Scan SRV records for services
  reverse_dns  - Reverse DNS lookup (PTR records)
  ip_neighbors - Scan neighboring IP addresses
  subdomain    - Enumerate common subdomains
'''
    )
    
    parser.add_argument('domain', help='Domain to analyze')
    parser.add_argument('-d', '--depth', type=int, default=2,
                        help='Recursion depth (default: 2)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output file (default: stdout for text, graph.png for images)')
    parser.add_argument('-f', '--format', type=str, default='text',
                        choices=['text', 'dot', 'png', 'svg'],
                        help='Output format (default: text)')
    parser.add_argument('-s', '--strategies', type=str, default=None,
                        help='Comma-separated list of strategies (default: all)')
    parser.add_argument('-e', '--engine', type=str, default='dot',
                        choices=['dot', 'neato', 'circo', 'twopi', 'fdp', 'sfdp'],
                        help='Graphviz layout engine (default: dot)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress progress messages')
    
    args = parser.parse_args()
    
    # Validate domain
    if not is_valid_domain(args.domain):
        print(f"Error: Invalid domain: {args.domain}", file=sys.stderr)
        sys.exit(1)
    
    # Parse strategies
    strategies = None
    if args.strategies:
        strategies = [s.strip() for s in args.strategies.split(',')]
        for s in strategies:
            if s not in ALL_STRATEGIES:
                print(f"Error: Unknown strategy: {s}", file=sys.stderr)
                print(f"Available: {', '.join(ALL_STRATEGIES.keys())}", file=sys.stderr)
                sys.exit(1)
    
    # Run mapper
    mapper = DNSMapper(
        target=args.domain,
        depth=args.depth,
        strategies=strategies,
        verbose=not args.quiet
    )
    
    result = mapper.run()
    
    # Output results
    if args.format == 'text':
        report = mapper.get_text_report()
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report saved to: {args.output}", file=sys.stderr)
        else:
            print(report)
    
    else:
        # Generate graph
        graph = create_graph(
            target=args.domain,
            domains=result.domains,
            ips=result.ips,
            edges=result.edges,
            engine=args.engine
        )
        
        output_path = args.output or 'dns_graph'
        # Remove extension if provided
        if output_path.endswith(f'.{args.format}'):
            output_path = output_path[:-len(args.format)-1]
        
        output_file = graph.render(output_path, format=args.format)
        print(f"Graph saved to: {output_file}", file=sys.stderr)


if __name__ == '__main__':
    main()
