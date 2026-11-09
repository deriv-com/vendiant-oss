#!/usr/bin/env python3
"""
Demo script to showcase actual SSL Labs and testssl.sh scanning capabilities.
Comprehensive SSL/TLS security assessment using testssl.sh and enhanced security checks.
MAINLY FOR BULK SCANNING REPORT GENERATION
Contains only orchestration and display logic:
    Tool availability checks (testssl.sh path verification)
    Scanner instantiation (VendorRiskScanner(testssl_path=testssl_path))
    Scan invocation (scanner.scan_domain(domain, full_scan=True))
    Result display (printing scan results to console)
    Report generation (scanner.generate_report(domain, format="text"))
    Threading management for bulk scans
    File I/O for reading domain lists and saving reports

"""

# =============================================================================
# CONFIGURATION SECTION - MODIFY THESE SETTINGS AS NEEDED
# =============================================================================

# SCAN MODE CONFIGURATION
# Choose one of the following modes:


# SINGLE DOMAIN CONFIGURATION (used when SCAN_MODE = "single")


# BULK SCAN CONFIGURATION (used when SCAN_MODE = "bulk")
DOMAINS_FILE = "alive_subdomains.txt"  # Path to your domains file (one domain per line)
MAX_WORKERS = 10  # Number of concurrent scans (recommended: 3-8)
DELAY_BETWEEN_SCANS = 1  # Delay in seconds between scan starts (recommended: 0.5-2)

# OPTIONAL: Create a sample domains file if it doesn't exist


# =============================================================================
# QUICK SETUP GUIDE:
# 
# For Single Domain Scanning:
# 1. Set SCAN_MODE = "single"
# 2. Set SINGLE_DOMAIN = "yourdomain.com" 
# 3. Run: python scanner_test_and_demo_local.py
#
# For Bulk Domain Scanning:
# 1. Set SCAN_MODE = "bulk"
# 2. Create a text file with domains (one per line) OR let the script create
#    a sample file using SAMPLE_DOMAINS
# 3. Set DOMAINS_FILE = "your_domains_file.txt"
# 4. Adjust MAX_WORKERS and DELAY_BETWEEN_SCANS if needed
# 5. Run: python scanner_test_and_demo_local.py
#
# =============================================================================
# END CONFIGURATION SECTION
# =============================================================================

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'custom_integrations'))
from logger_config import setup_logger

# Import our scanner components
from vendor_risk_scanner_local import VendorRiskScanner, log_filename
import config_local as config

# Setup logger using custom configuration
logger = setup_logger()

# import json  # No longer needed - text output only
import time
import concurrent.futures
from threading import Lock
import threading
import psutil  # For system resource detection
import json # Added for JSON report generation

# Global lock for thread-safe printing
print_lock = Lock()

def safe_print(*args, **kwargs):
    """Thread-safe printing for concurrent operations."""
    with print_lock:
        print(*args, **kwargs)

def extract_main_domain(domain):
    """Extract the main domain from a subdomain for grouping purposes."""
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('//', 1)[1].split('/')[0]
    
    # Split domain parts
    parts = domain.lower().split('.')
    
    # Handle different TLD scenarios
    if len(parts) >= 2:
        # For domains like subdomain.example.com -> example.com
        # For domains like example.co.uk -> example.co.uk
        # For domains like subdomain.example.co.uk -> example.co.uk
        
        # Common multi-part TLDs
        multi_part_tlds = [
            'co.uk', 'co.za', 'com.au', 'co.in', 'co.jp', 'com.br',
            'org.uk', 'net.au', 'gov.uk', 'edu.au', 'ac.uk'
        ]
        
        # Check if domain ends with a multi-part TLD
        domain_suffix = '.'.join(parts[-2:])
        if domain_suffix in multi_part_tlds and len(parts) >= 3:
            # For something like subdomain.example.co.uk
            return '.'.join(parts[-3:])
        elif len(parts) >= 2:
            # For regular domains like subdomain.example.com
            return '.'.join(parts[-2:])
    
    return domain

def get_domain_group_filename(domain):
    """Get the filename for a domain group (main domain)."""
    main_domain = extract_main_domain(domain)
    safe_domain = main_domain.replace('.', '_').replace(':', '_').replace('/', '_')
    return f"{safe_domain}_domain_group_report.txt"

def optimize_threading_config(domain_count, max_workers=None):
    """Optimize threading configuration based on system resources and domain count."""
    try:
        import psutil
        cpu_count = psutil.cpu_count(logical=True)
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Calculate optimal worker count if not specified
        if max_workers is None:
            # Base on CPU cores but cap for memory and API limits
            if domain_count < 10:
                optimal_workers = min(3, cpu_count)
            elif domain_count < 50:
                optimal_workers = min(5, cpu_count)
            elif domain_count < 200:
                optimal_workers = min(8, cpu_count, int(memory_gb // 2))
            else:
                optimal_workers = min(12, cpu_count, int(memory_gb // 2))
        else:
            optimal_workers = max_workers
        
        # Calculate optimal delay based on worker count and domain count
        if domain_count < 20:
            optimal_delay = 0.5
        elif domain_count < 100:
            optimal_delay = 1.0
        else:
            optimal_delay = 1.5
        
        # Adjust delay based on worker count (more workers = slightly more delay to avoid API limits)
        optimal_delay = optimal_delay * (optimal_workers / 5.0)
        
        safe_print(f"Threading optimization:")
        safe_print(f"  System: {cpu_count} CPU cores, {memory_gb:.1f}GB RAM")
        safe_print(f"  Optimal workers: {optimal_workers}")
        safe_print(f"  Optimal delay: {optimal_delay:.1f}s")
        
        return optimal_workers, optimal_delay
        
    except ImportError:
        safe_print("psutil not available, using conservative defaults")
        return max_workers or 5, 1.0
    except Exception as e:
        safe_print(f"Threading optimization failed: {e}, using defaults")
        return max_workers or 5, 1.0

def load_domains_from_file(file_path):
    """Load domains from a text file."""
    domains = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):  # Skip empty lines and comments
                    domains.append(domain)
        return domains
    except FileNotFoundError:
        safe_print(f"ERROR: File {file_path} not found")
        return []
    except Exception as e:
        safe_print(f"ERROR: Failed to read {file_path}: {e}")
        return []

def calculate_domain_group_average_score(domain_results):
    """Calculate average score for a main domain across all its subdomains."""
    if not domain_results:
        return None
        
    total_score = sum([result.get('risk_score', 0) for result in domain_results])
    avg_score = round(total_score / len(domain_results), 1) if domain_results else 0
    
    # Get the main domain name
    main_domain = extract_main_domain(domain_results[0]['domain'])
    
    # Collect all subdomains
    subdomains = [result['domain'] for result in domain_results]
    
    # Aggregate risk factors from all subdomains
    all_risk_factors = []
    risk_levels = []
    
    for result in domain_results:
        all_risk_factors.extend(result.get('risk_factors', []))
        if result.get('risk_level'):
            risk_levels.append(result['risk_level'])
    
    # Determine overall risk level based on average score
    if avg_score >= 800:
        avg_risk_level = "Low"
    elif avg_score >= 600:
        avg_risk_level = "Medium"
    elif avg_score >= 400:
        avg_risk_level = "High"
    else:
        avg_risk_level = "Critical"
    
    return {
        'main_domain': main_domain,
        'subdomains': subdomains,
        'subdomain_count': len(subdomains),
        'average_score': avg_score,
        'overall_risk_level': avg_risk_level,
        'individual_scores': [result.get('risk_score', 0) for result in domain_results],
        'individual_risk_levels': risk_levels,
        'aggregated_risk_factors': list(set(all_risk_factors)),  # Remove duplicates
        'timestamp': time.time()
    }

def group_results_by_main_domain(all_results):
    """Group scan results by main domain for subdomain averaging."""
    grouped = {}
    for domain, results in all_results.items():
        main_domain = extract_main_domain(domain)
        if main_domain not in grouped:
            grouped[main_domain] = []
        grouped[main_domain].append({
            'domain': domain,
            'risk_score': results.get('risk_score', 0),
            'risk_level': results.get('risk_level', 'Unknown'),
            'risk_factors': results.get('risk_factors', []),
            'scan_results': results
        })
    return grouped

def generate_domain_group_summary_report(grouped_results, results_dir="results"):
    """Generate a comprehensive summary report with subdomain averaging."""
    
    # Calculate averages for each main domain
    domain_averages = []
    for main_domain, domain_results in grouped_results.items():
        avg_data = calculate_domain_group_average_score(domain_results)
        if avg_data:
            domain_averages.append(avg_data)
    
    # Calculate overall statistics
    total_main_domains = len(domain_averages)
    total_subdomains = sum([avg['subdomain_count'] for avg in domain_averages])
    
    # Count by risk levels
    risk_level_counts = {}
    for avg_data in domain_averages:
        risk_level = avg_data['overall_risk_level']
        risk_level_counts[risk_level] = risk_level_counts.get(risk_level, 0) + 1
    
    # Calculate overall score (average of all main domain averages)
    if domain_averages:
        overall_score = sum([avg['average_score'] for avg in domain_averages]) / len(domain_averages)
        overall_score = round(overall_score, 1)
    else:
        overall_score = 0
    
    # Determine overall risk level
    if overall_score >= 800:
        overall_risk_level = "Low"
    elif overall_score >= 600:
        overall_risk_level = "Medium"
    elif overall_score >= 400:
        overall_risk_level = "High"
    else:
        overall_risk_level = "Critical"
    
    # Generate comprehensive report
    report_lines = [
        "=" * 90,
        "VENDOR RISK ASSESSMENT SUMMARY REPORT (WITH SUBDOMAIN AVERAGING)",
        "=" * 90,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Main Domains Analyzed: {total_main_domains}",
        f"Total Subdomains Analyzed: {total_subdomains}",
        "",
        "SCORING SYSTEM:",
        "• Base Score: 950 points (perfect security)",
        "• Severity-based deductions:",
        "  - CRITICAL issues: -12 points each",
        "  - HIGH issues: -8 points each",
        "  - MEDIUM issues: -4 points each", 
        "  - LOW issues: -1 point each",
        "",
        "SUBDOMAIN AVERAGING:",
        "• Subdomains are grouped by main domain (e.g., api.example.com → example.com)",
        "• Each main domain gets an average score across all its subdomains",
        "• Overall statistics are calculated from main domain averages",
        "",
        "SUMMARY STATISTICS:",
        f"• Total Main Domains: {total_main_domains}",
        f"• Overall Security Score: {overall_score}/950 ({overall_risk_level} Risk)",
        f"• Risk Level Distribution:",
    ]
    
    # Add risk level distribution
    for risk_level in ['Low', 'Medium', 'High', 'Critical']:
        count = risk_level_counts.get(risk_level, 0)
        percentage = (count / total_main_domains * 100) if total_main_domains > 0 else 0
        report_lines.append(f"  - {risk_level} Risk: {count} domains ({percentage:.1f}%)")
    
    report_lines.extend([
        "",
        "DOMAIN GROUP BREAKDOWN:",
        "----------------------------------------------------------------------"
    ])
    
    # Sort domain averages by risk score (lowest first - highest risk)
    sorted_domains = sorted(domain_averages, key=lambda x: x['average_score'])
    
    for avg_data in sorted_domains:
        main_domain = avg_data['main_domain']
        avg_score = avg_data['average_score']
        risk_level = avg_data['overall_risk_level']
        subdomain_count = avg_data['subdomain_count']
        
        report_lines.append(f"\n{main_domain} (Average Score: {avg_score}/950, {risk_level} Risk)")
        report_lines.append("-" * 60)
        
        if subdomain_count > 1:
            report_lines.append(f"Subdomains ({subdomain_count}):")
            for i, (subdomain, score) in enumerate(zip(avg_data['subdomains'], avg_data['individual_scores'])):
                report_lines.append(f"  {i+1}. {subdomain}: {score}/950")
        else:
            report_lines.append(f"Single domain: {avg_data['subdomains'][0]}")
        
        # Show top risk factors for this domain group
        top_risk_factors = avg_data['aggregated_risk_factors'][:5]  # Top 5 risk factors
        if top_risk_factors:
            report_lines.append("Top Risk Factors:")
            for factor in top_risk_factors:
                report_lines.append(f"  • {factor}")
    
    report_lines.extend([
        "",
        "=" * 90,
        "END OF VENDOR RISK ASSESSMENT SUMMARY",
        "=" * 90
    ])
    
    # Save the summary report
    summary_file = os.path.join(results_dir, "vendor_risk_summary_with_averaging.txt")
    with open(summary_file, 'w') as f:
        f.write('\n'.join(report_lines))
    
    safe_print(f"Domain group summary report saved: {summary_file}")
    
    # Also save JSON data for programmatic access
    json_data = {
        "generated_at": time.strftime('%Y-%m-%d %H:%M:%S'),
        "total_main_domains": total_main_domains,
        "total_subdomains": total_subdomains,
        "overall_score": overall_score,
        "overall_risk_level": overall_risk_level,
        "risk_level_distribution": risk_level_counts,
        "domain_averages": domain_averages
    }
    
    json_file = os.path.join(results_dir, "vendor_risk_summary_with_averaging.json")
    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    safe_print(f"Domain group summary JSON saved: {json_file}")
    
    return json_data

def demo_bulk_scan(domains_file, max_workers=5, delay_between_scans=1):
    """Perform bulk scanning of multiple domains from a text file with enhanced threading."""
    safe_print("VENDOR RISK SCANNER - ENHANCED BULK DOMAIN SCANNING")
    safe_print("=" * 70)
    safe_print(f"Session Log File: {log_filename}")
    safe_print(f"All scanning activities will be logged to: {log_filename}")
    safe_print("=" * 70)
    
    # Load domains from file
    domains = load_domains_from_file(domains_file)
    if not domains:
        safe_print("No domains to scan")
        return False
    
    safe_print(f"Loaded {len(domains)} domains from {domains_file}")
    
    # Log bulk scan session start
    logger.info(f"BULK SCAN SESSION STARTED")
    logger.info(f"Domains file: {domains_file}")
    logger.info(f"Total domains to scan: {len(domains)}")
    logger.info(f"Domains: {', '.join(domains[:10])}{'...' if len(domains) > 10 else ''}")
    
    # Optimize threading configuration based on domain count and system resources
    if max_workers == 5 and delay_between_scans == 1:  # Using defaults
        optimized_workers, optimized_delay = optimize_threading_config(len(domains))
    else:  # User specified values
        optimized_workers, optimized_delay = optimize_threading_config(len(domains), max_workers)
        # Keep user's delay if they specified it
        if delay_between_scans != 1:
            optimized_delay = delay_between_scans
    
    safe_print(f"Threading configuration:")
    safe_print(f"  Workers: {optimized_workers}")
    safe_print(f"  Delay: {optimized_delay:.1f}s")
    safe_print("=" * 70)
    
    # Check testssl.sh availability
    safe_print("Checking testssl.sh availability...")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
    
    if not os.path.exists(testssl_path):
        safe_print(f"ERROR: testssl.sh not found at {testssl_path}")
        safe_print("Please ensure testssl.sh is available")
        return False
    
    safe_print(f"SUCCESS: testssl.sh found at {testssl_path}")
    
    # Initialize scanner with testssl.sh path
    scanner = VendorRiskScanner(testssl_path=testssl_path)
    
    # Results storage
    all_results = {}
    failed_domains = []
    
    def scan_single_domain(domain):
        """Scan a single domain and return results - optimized for threading."""
        import threading
        import os
        thread_id = threading.current_thread().name
        
        try:
            safe_print(f"[{thread_id}] Starting scan for {domain}...")
            logger.info(f"[{thread_id}] Starting scan for domain: {domain}")
            start_time = time.time()
            
            # Ensure results directory exists
            results_dir = "results"
            os.makedirs(results_dir, exist_ok=True)
            
            # Create a fresh scanner instance for this thread to avoid conflicts
            thread_scanner = VendorRiskScanner(testssl_path=testssl_path)
            
            # Set up progress monitoring
            def progress_monitor():
                elapsed = time.time() - start_time
                if elapsed > 30:  # Every 30 seconds after first 30 seconds
                    safe_print(f"[{thread_id}] {domain}: Still scanning... {elapsed:.0f}s elapsed")
            
            # Perform scan with timeout protection and progress monitoring
            try:
                # Start progress monitoring timer
                import threading
                progress_timer = threading.Timer(30.0, progress_monitor)
                progress_timer.daemon = True
                progress_timer.start()
                
                # Use threading-based timeout instead of signal (which doesn't work in threads)
                results = thread_scanner.scan_domain(domain, full_scan=True)
                
                # Cancel progress monitoring
                progress_timer.cancel()
                
            except TimeoutError as e:
                safe_print(f"[{thread_id}] ✗ {domain}: TIMEOUT - {str(e)}")
                logger.error(f"[{thread_id}] Scan timeout for {domain}: {str(e)}")
                return domain, None, f"Scan timed out: {str(e)}"
            except Exception as scan_error:
                safe_print(f"[{thread_id}] ✗ {domain}: Scan failed - {str(scan_error)}")
                logger.error(f"[{thread_id}] Scan failed for {domain}: {str(scan_error)}")
                return domain, None, f"Scan failed: {str(scan_error)}"
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            # Get summary info safely
            risk_score = results.get('risk_score', 0)
            risk_level = results.get('risk_level', 'Unknown')
            vuln_count = len(results.get('testssl', {}).get('vulnerabilities', {}))
            
            # Generate vulnerability info only if there are vulnerabilities
            vuln_info = f" - Vulns: {vuln_count}" if vuln_count > 0 else ""
            
            # Log success with thread info
            safe_print(f"[{thread_id}] ✓ {domain}: {risk_score}/950 ({risk_level}){vuln_info} - {scan_duration:.1f}s")
            
            # Log detailed info (keep vulnerability count in logs for tracking)
            logger.info(f"[{thread_id}] Scan completed for {domain}: Risk Score: {risk_score}/950 ({risk_level}), Vulnerabilities: {vuln_count}, Duration: {scan_duration:.1f}s")
            
            # Save individual report using the scanner's built-in report generation
            try:
                # Use the scanner's text report generation instead of duplicating code
                comprehensive_report = thread_scanner.generate_report(domain, format="text")

                # Save as grouped domain report (subdomains go into main domain file)
                main_domain = extract_main_domain(domain)
                group_filename = get_domain_group_filename(domain)
                report_file = os.path.join(results_dir, group_filename)
                
                # Check if file already exists (for subdomain grouping)
                file_mode = 'a' if os.path.exists(report_file) else 'w'
                
                with open(report_file, file_mode) as f:
                    if file_mode == 'a':
                        f.write("\n\n" + "="*80 + "\n")
                        f.write(f"ADDITIONAL DOMAIN/SUBDOMAIN: {domain}\n")
                        f.write("="*80 + "\n")
                    f.write(comprehensive_report)
                
                safe_print(f"[{thread_id}] Domain group report updated: {report_file}")
                safe_print(f"[{thread_id}] {domain} grouped under: {main_domain}")
                logger.info(f"[{thread_id}] Report saved for {domain} in group file: {report_file} (main domain: {main_domain})")
                
            except Exception as report_error:
                safe_print(f"[{thread_id}] Warning: Failed to save report for {domain}: {str(report_error)}")
                logger.warning(f"[{thread_id}] Failed to save report for {domain}: {str(report_error)}")
                # Don't fail the whole scan if just report saving fails
            
            return domain, results, None
            
        except Exception as e:
            safe_print(f"[{thread_id}] ✗ {domain}: FAILED - {str(e)}")
            return domain, None, str(e)
        finally:
            # Cleanup thread resources if needed
            try:
                if 'thread_scanner' in locals():
                    del thread_scanner
            except:
                pass
    
    # Start bulk scanning
    overall_start_time = time.time()
    
    # Enhanced threading with batch processing for better performance
    safe_print("Starting enhanced threaded scanning...")
    
    # Process domains in batches to manage memory and connections better
    batch_size = optimized_workers * 3  # Process 3x worker count per batch
    domain_batches = [domains[i:i + batch_size] for i in range(0, len(domains), batch_size)]
    
    safe_print(f"Processing {len(domains)} domains in {len(domain_batches)} batches of {batch_size}")
    
    for batch_num, batch_domains in enumerate(domain_batches, 1):
        safe_print(f"\n--- Processing Batch {batch_num}/{len(domain_batches)} ({len(batch_domains)} domains) ---")
        
        # Monitor system performance before batch
        performance_start = monitor_system_performance()
        
        # Use ThreadPoolExecutor for concurrent scanning of current batch
        with concurrent.futures.ThreadPoolExecutor(max_workers=optimized_workers, thread_name_prefix="VendorScan") as executor:
            # Submit all scanning tasks for this batch
            future_to_domain = {}
            
            for i, domain in enumerate(batch_domains):
                # Stagger submissions to avoid overwhelming APIs
                if i > 0 and optimized_delay > 0:
                    time.sleep(optimized_delay / optimized_workers)  # Reduced delay for threading
                future = executor.submit(scan_single_domain, domain)
                future_to_domain[future] = domain
            
            # Collect results as they complete
            batch_completed = 0
            batch_start_time = time.time()
            for future in concurrent.futures.as_completed(future_to_domain, timeout=1800):  # 30 min timeout per batch
                try:
                    domain, results, error = future.result(timeout=900)  # 15 min timeout per domain
                    batch_completed += 1
                    total_completed = (batch_num - 1) * batch_size + batch_completed
                    batch_elapsed = time.time() - batch_start_time
                    
                    if results:
                        all_results[domain] = results
                        risk_score = results.get('risk_score', 0)
                        risk_level = results.get('risk_level', 'Unknown')
                        safe_print(f"✓ {domain} completed successfully ({total_completed}/{len(domains)}) - {risk_score}/950 ({risk_level}) - Batch time: {batch_elapsed:.1f}s")
                    else:
                        failed_domains.append({'domain': domain, 'error': error})
                        safe_print(f"✗ {domain} failed: {error} ({total_completed}/{len(domains)}) - Batch time: {batch_elapsed:.1f}s")
                    
                except concurrent.futures.TimeoutError:
                    domain = future_to_domain[future]
                    error_msg = "Domain scan timed out after 15 minutes"
                    failed_domains.append({'domain': domain, 'error': error_msg})
                    safe_print(f"✗ {domain} timed out ({total_completed}/{len(domains)})")
                except Exception as e:
                    domain = future_to_domain[future]
                    error_msg = f"Unexpected error: {str(e)}"
                    failed_domains.append({'domain': domain, 'error': error_msg})
                    safe_print(f"✗ {domain} error: {error_msg} ({total_completed}/{len(domains)})")
        
        # Brief pause between batches to let system recover
        if batch_num < len(domain_batches):
            # Monitor system performance after batch
            performance_end = monitor_system_performance()
            safe_print(f"Batch {batch_num} completed. Pausing {optimized_delay} seconds before next batch...")
            time.sleep(optimized_delay)
        else:
            safe_print(f"Final batch {batch_num} completed!")
            monitor_system_performance()
    
    overall_end_time = time.time()
    total_duration = overall_end_time - overall_start_time
    
    # Generate summary
    safe_print("\n" + "=" * 70)
    safe_print("BULK SCAN SUMMARY")
    safe_print("=" * 70)
    safe_print(f"Total domains scanned: {len(domains)}")
    safe_print(f"Successful scans: {len(all_results)}")
    safe_print(f"Failed scans: {len(failed_domains)}")
    safe_print(f"Total time: {total_duration:.1f} seconds")
    safe_print(f"Average time per domain: {total_duration/len(domains):.1f} seconds")
    
    # Risk level summary
    risk_levels = {}
    for domain, results in all_results.items():
        risk_level = results.get('risk_level', 'Unknown')
        risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
    
    safe_print("\nRisk Level Distribution:")
    for level, count in sorted(risk_levels.items()):
        safe_print(f"  {level}: {count} domains")
    
    # Top 10 highest risk domains
    if all_results:
        sorted_domains = sorted(all_results.items(), key=lambda x: x[1].get('risk_score', 0))
        safe_print("\nTop 10 Highest Risk Domains:")
        for domain, results in sorted_domains[:10]:
            risk_score = results.get('risk_score', 0)
            risk_level = results.get('risk_level', 'Unknown')
            vuln_count = len(results.get('testssl', {}).get('vulnerabilities', {}))
            vuln_info = f" - Vulns: {vuln_count}" if vuln_count > 0 else ""
            safe_print(f"  {domain}: {risk_score}/950 ({risk_level}){vuln_info}")
    
    # Failed domains
    if failed_domains:
        safe_print("\nFailed Domains:")
        for failed in failed_domains:
            safe_print(f"  {failed['domain']}: {failed['error']}")
    
    # Define results_dir before using it
    results_dir = "results"
    safe_print(f"\nIndividual domain reports saved in: {results_dir}/")
    safe_print(f"Total individual reports: {len(all_results)}")
    
    # Log final bulk scan summary
    logger.info("BULK SCAN SESSION COMPLETED")
    logger.info(f"Total domains processed: {len(domains)}")
    logger.info(f"Successful scans: {len(all_results)}")
    logger.info(f"Failed scans: {len(failed_domains)}")
    logger.info(f"Total duration: {total_duration:.1f} seconds")
    logger.info(f"Average time per domain: {total_duration/len(domains):.1f} seconds")
    logger.info(f"Reports saved to: {results_dir}/")
    logger.info(f"Session log saved to: {log_filename}")
    
    safe_print(f"\nSession log has been saved to: {log_filename}")
    
    # Group results by main domain for averaging
    grouped_results = group_results_by_main_domain(all_results)
    
    # Generate and save summary report with subdomain averaging
    generate_domain_group_summary_report(grouped_results, results_dir)
    
    return True

def demo_full_scan(domain):
    """Demonstrate full scanning capabilities on a test domain."""
    print("VENDOR RISK SCANNER - LIVE DEMO")
    print("=" * 60)
    print(f"Target Domain: {domain}")
    print(f"Session Log File: {log_filename}")
    print("This scanner uses:")
    print("  - testssl.sh")
    print("  - Security Headers Analysis")
    print("  - HSTS Preload Check")
    print("  - Enhanced Security Checks")
    print("")
    
    # Check testssl.sh availability
    current_dir = os.path.dirname(os.path.abspath(__file__))
    testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
    
    if not os.path.exists(testssl_path):
        print(f"ERROR: testssl.sh not found at {testssl_path}")
        print("Please ensure testssl.sh is available")
        return False
    
    print(f"SUCCESS: testssl.sh found at {testssl_path}")
    
    # Initialize scanner with testssl.sh path
    scanner = VendorRiskScanner(testssl_path=testssl_path)
    
    try:
        # Start the scan
        print(f"\nStarting comprehensive scan of {domain}...")
        start_time = time.time()
        
        # Perform full scan
        results = scanner.scan_domain(domain, full_scan=True)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print(f"\nScan completed in {scan_duration:.1f} seconds")
        print("=" * 60)
        
        # Display results
        print("SCAN RESULTS SUMMARY:")
        print("-" * 30)
        
        # Overall risk assessment
        risk_score = results.get('risk_score', 0)
        risk_level = results.get('risk_level', 'Unknown')
        
        print()
        print("*" * 60)
        print(f"   VENDOR SECURITY SCORE: {risk_score}/950")
        print(f"   RISK LEVEL: {risk_level.upper()} RISK")
        print("*" * 60)
        print()
        
        # Enhanced Security Checks Results
        enhanced_checks = results.get('enhanced_security_checks', {})
        if 'error' in enhanced_checks:
            print(f"Enhanced Security Checks: ERROR - {enhanced_checks['error']}")
        else:
            summary = enhanced_checks.get('summary', {})
            issues_found = summary.get('issues_found', 0)
            total_checks = summary.get('total_checks', 0)
            print(f"ENHANCED SECURITY CHECKS: {issues_found}/{total_checks} issues found")
        
        # testssl.sh Results
        testssl = results.get('testssl', {})
        if 'error' in testssl:
            print(f"testssl.sh: ERROR - {testssl['error']}")
        else:
            vulns = testssl.get('vulnerabilities', {})
            if vulns:
                critical_vulns = [v for v in vulns.values() if v.get('severity') == 'CRITICAL']
                high_vulns = [v for v in vulns.values() if v.get('severity') == 'HIGH']
                print(f"testssl.sh: {len(critical_vulns)} critical, {len(high_vulns)} high severity issues")
            else:
                print("testssl.sh: Scan completed")
        
        # Certificate Details
        cert_details = results.get('certificate_details', {})
        if 'error' in cert_details:
            print(f"Certificate Details: ERROR - {cert_details['error']}")
        else:
            print("Certificate Details:")
            print(f"  Subject: {cert_details.get('subject', 'Unknown')}")
            print(f"  Issuer: {cert_details.get('issuer', 'Unknown')}")
            print(f"  Key Algorithm: {cert_details.get('key_algorithm', 'Unknown')}")
            print(f"  Key Size: {cert_details.get('key_size', 'Unknown')}")
            print(f"  Days Until Expiry: {cert_details.get('days_until_expiry', 'Unknown')}")
        
        # Certificate Inspection (legacy)
        cert_info = results.get('detailed_certificate', {})
        if 'error' in cert_info:
            print(f"Certificate Inspection: ERROR - {cert_info['error']}")
        else:
            issues = cert_info.get('security_issues', [])
            print(f"Certificate Inspection: {len(issues)} security issues found")
        
        # Security Headers
        headers = results.get('security_headers', {})
        if 'error' in headers:
            print(f"Security Headers: ERROR - {headers['error']}")
        else:
            missing = headers.get('missing', [])
            if missing:
                print(f"Security Headers: {len(missing)} headers missing")
            else:
                print("Security Headers: All present")
        
        # HSTS Preload
        hsts = results.get('hsts_preload', {})
        if 'error' in hsts:
            print(f"HSTS Preload: ERROR - {hsts['error']}")
        else:
            preloaded = hsts.get('preloaded', False)
            status = "Preloaded" if preloaded else "Not preloaded"
            print(f"HSTS Preload: {status}")
        
        print()
        
        # Risk Factors
        risk_factors = results.get('risk_factors', [])
        if risk_factors:
            print("RISK FACTORS:")
            for factor in risk_factors[:5]:  # Show top 5
                print(f"  - {factor}")
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print("\nRECOMMENDATIONS:")
            for rec in recommendations[:5]:  # Show top 5
                print(f"  - {rec}")
        
        print("\n" + "=" * 60)
        
        print(f"\nAssessment completed! Results displayed above.")
        print("Use demo_bulk_scan() for generating saved reports.")
        
        return True
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return False
    except Exception as e:
        print(f"\nScan failed: {str(e)}")
        return False



def test_setup():
    """Test setup and show available tools."""
    print("SETUP TEST")
    print("=" * 50)
    
    tools_status = {}
    
    # Check testssl.sh
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
    if os.path.exists(testssl_path) and os.access(testssl_path, os.X_OK):
        tools_status["testssl.sh"] = "Available and executable"
    else:
        tools_status["testssl.sh"] = "Not found or not executable"
    
    # Check other tools
    import subprocess
    for tool in ["curl", "wget", "openssl"]:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode == 0:
                tools_status[tool] = f"Available at {result.stdout.strip()}"
            else:
                tools_status[tool] = "Not found"
        except Exception as e:
            tools_status[tool] = f"Error checking: {e}"
    
    # Print results
    print("Tool Availability:")
    for tool, status in tools_status.items():
        print(f"  {tool}: {status}")
    
    all_good = all("Available" in status for status in tools_status.values())
    
    if all_good:
        print("\nAll tools are ready!")
        return True
    else:
        print("\nSome tools are missing. Please install them first.")
        return False

def monitor_system_performance():
    """Monitor and display system performance metrics during scanning."""
    try:
        import psutil
        import threading
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_available_gb = memory.available / (1024**3)
        
        # Active threads
        active_threads = threading.active_count()
        
        # Network connections (if available)
        try:
            connections = len(psutil.net_connections())
        except:
            connections = "N/A"
        
        safe_print(f"System Status: CPU: {cpu_percent}%, RAM: {memory_percent}% used, "
                  f"{memory_available_gb:.1f}GB free, Threads: {active_threads}, Connections: {connections}")
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_available_gb': memory_available_gb,
            'active_threads': active_threads,
            'connections': connections
        }
        
    except ImportError:
        safe_print("System monitoring unavailable (psutil not installed)")
        return None
    except Exception as e:
        safe_print(f"System monitoring error: {e}")
        return None



def main():
    """Main function with automated scanning - supports single domain or bulk scanning from file."""
    print("VENDOR RISK SCANNER - CONFIGURATION-BASED MODE")
    
    # Log main session start
    logger.info("VENDOR RISK SCANNER MAIN SESSION STARTED")
        
   
    domains_file = DOMAINS_FILE
    max_workers = MAX_WORKERS
    delay_between_scans = DELAY_BETWEEN_SCANS

    logger.info(f"Configuration: domains_file={domains_file}, max_workers={max_workers}, delay={delay_between_scans}s")
    
    print(f"Domains File: {domains_file}")
    print(f"Configuration: {max_workers} workers, {delay_between_scans}s delay")
    print(f"Session Log File: {log_filename}")
    print("=" * 60)
    
    result = demo_bulk_scan(domains_file, max_workers, delay_between_scans)
    
    logger.info(f"VENDOR RISK SCANNER MAIN SESSION COMPLETED - Success: {result}")
    
    return result
        
    
        
if __name__ == "__main__":
    main() 