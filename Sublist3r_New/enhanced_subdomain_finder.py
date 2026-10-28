#!/usr/bin/env python3
"""
Enhanced Subdomain Finder
=========================

This script uses multiple sources to find subdomains without requiring API keys:
- Sublist3r (with all search engines + new ones)
- Certificate Transparency (crt.sh)
- HackerTarget API
- RapidDNS
- BufferOver DNS
- Anubis
- Wayback Machine
- AlienVault OTX
- Enhanced bruteforce wordlist
- DNS zone transfer testing
- Alternative DNS record enumeration

Usage: python enhanced_subdomain_finder.py <domain>
"""

import sys
import argparse
from subdomains_sub import find_all_subdomains, find_alive_subdomains, save_subdomains_to_file, save_detailed_results

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced subdomain enumeration without API keys",
        epilog="Example: python enhanced_subdomain_finder.py example.com"
    )
    parser.add_argument("domain", help="Target domain to enumerate subdomains for")
    parser.add_argument("--no-alive-check", action="store_true", 
                       help="Skip checking if subdomains are alive (faster)")
    parser.add_argument("--threads", type=int, default=30,
                       help="Number of threads for alive checking (default: 30)")
    parser.add_argument("--output-dir", default="../Results",
                       help="Output directory for results (default: ../Results)")
    
    args = parser.parse_args()
    domain = args.domain.lower().strip()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                Enhanced Subdomain Finder                     ║
║                  No API Keys Required!                       ║
╚══════════════════════════════════════════════════════════════╝

Target Domain: {domain}
Output Directory: {args.output_dir}
Alive Check: {'Disabled' if args.no_alive_check else 'Enabled'}
Threads: {args.threads}

Starting comprehensive enumeration...
This process uses the following sources:
• Sublist3r (Google, Bing, Yahoo, Ask, Baidu, VirusTotal, etc.)
• Certificate Transparency (crt.sh)
• HackerTarget API
• RapidDNS
• BufferOver DNS
• Anubis
• Wayback Machine
• AlienVault OTX
• Enhanced Bruteforce Wordlist
• DNS Zone Transfer Testing
• Alternative DNS Records

""")
    
    try:
        # Find all subdomains
        print(" Starting subdomain enumeration...")
        print(" This may take 2-5 minutes depending on network connectivity...")
        all_subdomains = find_all_subdomains(domain)
        print(f" Found {len(all_subdomains)} unique subdomains!")
        
        # Save all subdomains
        save_subdomains_to_file(all_subdomains, "All Domains", f"{domain}_all_subdomains.txt")
        print(f"💾 All subdomains saved to {args.output_dir}/All Domains/{domain}_all_subdomains.txt")
        
        alive_subdomains = []
        if not args.no_alive_check and all_subdomains:
            print("\n Checking which subdomains are alive...")
            alive_subdomains = find_alive_subdomains(all_subdomains, max_workers=args.threads)
            print(f" Found {len(alive_subdomains)} alive subdomains!")
            
            # Save alive subdomains
            save_subdomains_to_file(alive_subdomains, "Alive Domains", f"{domain}_alive_subdomains.txt")
            print(f" Alive subdomains saved to {args.output_dir}/Alive Domains/{domain}_alive_subdomains.txt")
        
        # Calculate statistics
        total = len(all_subdomains)
        alive = len(alive_subdomains)
        dead = total - alive
        
        if total > 0:
            alive_percent = (alive / total) * 100
            dead_percent = 100 - alive_percent
        else:
            alive_percent = dead_percent = 0
        
        # Save detailed report
        sources_stats = {
            "Total Discovered": total,
            "Alive": alive,
            "Dead": dead
        }
        save_detailed_results(domain, all_subdomains, alive_subdomains, sources_stats)
        
        # Display final results
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                        FINAL RESULTS                         ║
╚══════════════════════════════════════════════════════════════╝

📊 Statistics for {domain}:
   Total Subdomains Found: {total}
   Alive Subdomains: {alive} ({alive_percent:.1f}%)
   Dead Subdomains: {dead} ({dead_percent:.1f}%)

📁 Files Created:
   • All subdomains: {args.output_dir}/All Domains/{domain}_all_subdomains.txt
   • Alive subdomains: {args.output_dir}/Alive Domains/{domain}_alive_subdomains.txt  
   • Detailed report: {args.output_dir}/{domain}_comprehensive_report.txt

🎯 Success Rate: {alive_percent:.1f}% of discovered subdomains are responsive

""")
        
        if alive_subdomains:
            print("🌟 Top 10 Alive Subdomains:")
            for i, subdomain in enumerate(sorted(alive_subdomains)[:10], 1):
                print(f"   {i:2d}. {subdomain}")
            if len(alive_subdomains) > 10:
                print(f"   ... and {len(alive_subdomains) - 10} more!")
        
        print("\n✨ Enhanced subdomain enumeration completed successfully!")
        print("\n💡 Tip: Run 'python debug_network.py' to test connectivity if you got fewer results than expected.")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        print("\n🔧 Troubleshooting suggestions:")
        print("   1. Run 'python debug_network.py' to test connectivity")
        print("   2. Check your internet connection") 
        print("   3. Try running with --no-alive-check for faster results")
        sys.exit(1)

if __name__ == "__main__":
    main() 