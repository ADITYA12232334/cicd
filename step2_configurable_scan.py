#!/usr/bin/env python3
"""
Step 2: Configurable ZAP Security Scanner
This script adds configuration, scan types, and threshold gating.
"""

from zapv2 import ZAPv2
import time
import requests
import os
import sys
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Fallback if colorama not installed
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class ScanConfig:
    """Manages all configuration from environment variables and .env file"""
    
    def __init__(self):
        # Load from .env file if it exists
        load_dotenv()
        
        # Required settings
        self.target_url = self._get_required('ZAP_TARGET_URL')
        
        # Optional settings with defaults
        self.scan_type = self._get_optional('ZAP_SCAN_TYPE', 'standard')
        self.zap_host = self._get_optional('ZAP_HOST', 'localhost')
        self.zap_port = int(self._get_optional('ZAP_PORT', '8080'))
        
        # Threshold settings
        self.max_high = int(self._get_optional('ZAP_MAX_HIGH', '0'))
        self.max_medium = int(self._get_optional('ZAP_MAX_MEDIUM', '5'))
        self.max_low = int(self._get_optional('ZAP_MAX_LOW', '999'))
        
        # Report settings
        self.report_dir = self._get_optional('ZAP_REPORT_DIR', './reports')
        
        # Validate configuration
        self._validate()
    
    def _get_required(self, key):
        """Get required environment variable or exit"""
        value = os.getenv(key)
        if not value:
            print(f"{Fore.RED}❌ Error: Missing required environment variable: {key}")
            print(f"\nCreate a .env file with:")
            print(f"  {key}=http://example.com")
            sys.exit(2)
        return value
    
    def _get_optional(self, key, default):
        """Get optional environment variable with default"""
        return os.getenv(key, default)
    
    def _validate(self):
        """Validate all configuration settings"""
        # Validate scan type
        valid_types = ['quick', 'standard', 'full']
        if self.scan_type not in valid_types:
            print(f"{Fore.RED}❌ Error: Invalid scan type: {self.scan_type}")
            print(f"Valid types: {', '.join(valid_types)}")
            sys.exit(2)
        
        # Validate URL format
        if not self.target_url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}❌ Error: Target URL must start with http:// or https://")
            sys.exit(2)
        
        # Validate thresholds are non-negative
        if self.max_high < 0 or self.max_medium < 0 or self.max_low < 0:
            print(f"{Fore.RED}❌ Error: Thresholds must be non-negative integers")
            sys.exit(2)
    
    def display(self):
        """Display current configuration"""
        print(f"\n{Fore.CYAN}Configuration:")
        print(f"  Target URL:      {self.target_url}")
        print(f"  Scan Type:       {self.scan_type}")
        print(f"  Max High:        {self.max_high}")
        print(f"  Max Medium:      {self.max_medium}")
        print(f"  Max Low:         {self.max_low}")
        print(f"  Report Dir:      {self.report_dir}")

# ============================================================================
# SCAN TYPE CONFIGURATIONS
# ============================================================================

class ScanTypeConfig:
    """Defines configuration for different scan types"""
    
    TYPES = {
        'quick': {
            'name': 'Quick Scan',
            'description': 'Fast surface-level scan',
            'spider_max_depth': 1,
            'spider_max_duration': 2,  # minutes
            'active_scan': False,
            'duration_estimate': '~2 minutes'
        },
        'standard': {
            'name': 'Standard Scan',
            'description': 'Balanced scan for regular builds',
            'spider_max_depth': 2,
            'spider_max_duration': 5,  # minutes
            'active_scan': True,
            'duration_estimate': '~10 minutes'
        },
        'full': {
            'name': 'Full Scan',
            'description': 'Comprehensive security assessment',
            'spider_max_depth': 0,  # unlimited
            'spider_max_duration': 0,  # unlimited
            'active_scan': True,
            'duration_estimate': '30+ minutes'
        }
    }
    
    @staticmethod
    def get(scan_type):
        """Get configuration for a scan type"""
        return ScanTypeConfig.TYPES[scan_type]

# ============================================================================
# STEP 1: Wait for ZAP to be ready
# ============================================================================

def wait_for_zap(config):
    """
    ZAP takes time to start. This function waits until it's ready.
    """
    print("=" * 60)
    print(f"{Fore.CYAN}STEP 1: Waiting for ZAP to start...")
    print("=" * 60)
    
    for attempt in range(30):  # Try for 60 seconds (30 attempts × 2 seconds)
        try:
            response = requests.get(
                f'http://{config.zap_host}:{config.zap_port}/JSON/core/view/version/',
                timeout=5
            )
            if response.status_code == 200:
                version_data = response.json()
                print(f"{Fore.GREEN}✓ ZAP is ready! Version: {version_data.get('version', 'Unknown')}")
                return True
        except Exception:
            pass
        
        print(f"  Waiting... (attempt {attempt + 1}/30)")
        time.sleep(2)
    
    print(f"{Fore.RED}✗ ZAP didn't start in time!")
    return False

# ============================================================================
# STEP 2: Connect to ZAP
# ============================================================================

def connect_to_zap(config):
    """
    Create a connection to the ZAP API.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 2: Connecting to ZAP API...")
    print("=" * 60)
    
    zap = ZAPv2(
        proxies={
            'http': f'http://{config.zap_host}:{config.zap_port}',
            'https': f'http://{config.zap_host}:{config.zap_port}'
        }
    )
    print(f"{Fore.GREEN}✓ Connected to ZAP at {config.zap_host}:{config.zap_port}")
    return zap

# ============================================================================
# STEP 3: Access the target website
# ============================================================================

def access_target(zap, config):
    """
    Tell ZAP to visit the target website.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 3: Accessing target: {config.target_url}")
    print("=" * 60)
    
    zap.urlopen(config.target_url)
    time.sleep(2)
    print(f"{Fore.GREEN}✓ Accessed {config.target_url}")

# ============================================================================
# STEP 4: Run Spider Scan (discover pages)
# ============================================================================

def run_spider_scan(zap, config, scan_type_config):
    """
    Spider scan crawls the website to find all pages/URLs.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 4: Running Spider Scan...")
    print("=" * 60)
    print(f"  Type: {scan_type_config['name']}")
    print(f"  Max Depth: {scan_type_config['spider_max_depth'] or 'Unlimited'}")
    
    # Configure spider
    if scan_type_config['spider_max_depth'] > 0:
        zap.spider.set_option_max_depth(scan_type_config['spider_max_depth'])
    
    # Start spider
    scan_id = zap.spider.scan(config.target_url)
    print(f"Spider scan started with ID: {scan_id}")
    
    # Wait for spider to complete
    start_time = time.time()
    max_duration = scan_type_config['spider_max_duration'] * 60  # convert to seconds
    
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        elapsed = int(time.time() - start_time)
        print(f"  Progress: {progress}% (elapsed: {elapsed}s)", end='\r')
        
        # Check if we've exceeded max duration (only for non-zero duration)
        if max_duration > 0 and elapsed > max_duration:
            print(f"\n{Fore.YELLOW}⚠️  Spider scan reached max duration, stopping...")
            zap.spider.stop(scan_id)
            break
        
        time.sleep(2)
    
    print(f"\n{Fore.GREEN}✓ Spider scan completed!")
    
    # Get results
    urls = zap.spider.results(scan_id)
    print(f"  Found {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URLs")
    
    # Show first 5 URLs
    if len(urls) > 0:
        print(f"\n  Sample URLs found:")
        for url in urls[:5]:
            print(f"    - {url}")
        if len(urls) > 5:
            print(f"    ... and {len(urls) - 5} more")
    
    return urls

# ============================================================================
# STEP 5: Run Active Scan (find vulnerabilities)
# ============================================================================

def run_active_scan(zap, config, scan_type_config):
    """
    Active scan tests for actual security vulnerabilities.
    This can take a while!
    """
    if not scan_type_config['active_scan']:
        print("\n" + "=" * 60)
        print(f"{Fore.YELLOW}STEP 5: Skipping Active Scan (quick scan mode)")
        print("=" * 60)
        return
    
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 5: Running Active Scan...")
    print("=" * 60)
    print(f"{Fore.YELLOW}⚠️  This may take several minutes...")
    print(f"  Estimated duration: {scan_type_config['duration_estimate']}")
    
    scan_id = zap.ascan.scan(config.target_url)
    print(f"Active scan started with ID: {scan_id}")
    
    # Wait for active scan to complete
    last_progress = 0
    while int(zap.ascan.status(scan_id)) < 100:
        progress = int(zap.ascan.status(scan_id))
        
        # Only print when progress changes (to avoid spam)
        if progress != last_progress:
            print(f"  Progress: {progress}%")
            last_progress = progress
        
        time.sleep(5)
    
    print(f"{Fore.GREEN}✓ Active scan completed!")

# ============================================================================
# STEP 6: Get and analyze results
# ============================================================================

def get_alerts(zap, config):
    """
    Retrieve all security alerts found during the scan.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 6: Retrieving Security Alerts...")
    print("=" * 60)
    
    alerts = zap.core.alerts(baseurl=config.target_url)
    print(f"Total alerts found: {Fore.YELLOW}{len(alerts)}{Style.RESET_ALL}")
    
    return alerts

def analyze_alerts(alerts):
    """
    Count alerts by risk level.
    """
    risk_counts = {
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Informational': 0
    }
    
    for alert in alerts:
        risk = alert.get('risk', 'Informational')
        risk_counts[risk] += 1
    
    return risk_counts

def check_thresholds(risk_counts, config):
    """
    Check if vulnerabilities exceed configured thresholds.
    Returns (passed, details)
    """
    checks = []
    
    # Check high-risk
    high_pass = risk_counts['High'] <= config.max_high
    checks.append({
        'level': 'High',
        'count': risk_counts['High'],
        'max': config.max_high,
        'passed': high_pass,
        'color': Fore.RED
    })
    
    # Check medium-risk
    medium_pass = risk_counts['Medium'] <= config.max_medium
    checks.append({
        'level': 'Medium',
        'count': risk_counts['Medium'],
        'max': config.max_medium,
        'passed': medium_pass,
        'color': Fore.YELLOW
    })
    
    # Check low-risk
    low_pass = risk_counts['Low'] <= config.max_low
    checks.append({
        'level': 'Low',
        'count': risk_counts['Low'],
        'max': config.max_low,
        'passed': low_pass,
        'color': Fore.BLUE
    })
    
    all_passed = all(check['passed'] for check in checks)
    
    return all_passed, checks

def display_results(alerts, risk_counts, config):
    """
    Display a nice summary of the scan results.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}{Style.BRIGHT}SCAN RESULTS SUMMARY")
    print("=" * 60)
    
    print(f"\nTarget: {Fore.WHITE}{config.target_url}")
    print(f"Total Alerts: {Fore.YELLOW}{len(alerts)}")
    
    print(f"\n{Fore.CYAN}Alerts by Risk Level:")
    print(f"  {Fore.RED}🔴 High:          {risk_counts['High']}")
    print(f"  {Fore.YELLOW}🟠 Medium:        {risk_counts['Medium']}")
    print(f"  {Fore.BLUE}🟡 Low:           {risk_counts['Low']}")
    print(f"  {Fore.WHITE}ℹ️  Informational: {risk_counts['Informational']}")
    
    # Show some high-risk alerts if any
    high_risk_alerts = [a for a in alerts if a.get('risk') == 'High']
    if high_risk_alerts:
        print(f"\n{Fore.RED}{Style.BRIGHT}⚠️  HIGH RISK VULNERABILITIES FOUND:")
        print("-" * 60)
        for i, alert in enumerate(high_risk_alerts[:3], 1):
            print(f"\n{i}. {Fore.RED}{alert['alert']}")
            print(f"   {Fore.WHITE}URL: {alert['url']}")
            desc = alert['description'][:100].replace('\n', ' ')
            print(f"   {Fore.WHITE}Description: {desc}...")
        
        if len(high_risk_alerts) > 3:
            print(f"\n   {Fore.YELLOW}... and {len(high_risk_alerts) - 3} more high-risk issues")
    
    # Show threshold check results
    all_passed, checks = check_thresholds(risk_counts, config)
    
    print(f"\n{Fore.CYAN}Threshold Check:")
    for check in checks:
        status = f"{Fore.GREEN}✅" if check['passed'] else f"{Fore.RED}❌"
        result = "PASS" if check['passed'] else "FAIL - EXCEEDS LIMIT"
        print(f"  {status} {check['level']:7s} {check['count']}/{check['max']} ({result})")
    
    # Final result
    print("\n" + "=" * 60)
    if all_passed:
        print(f"{Fore.GREEN}{Style.BRIGHT}✅ SCAN PASSED - All thresholds met!")
    else:
        print(f"{Fore.RED}{Style.BRIGHT}❌ SCAN FAILED - Vulnerabilities exceed thresholds!")
    print("=" * 60)
    
    return all_passed

# ============================================================================
# STEP 7: Save reports
# ============================================================================

def save_reports(zap, alerts, config, risk_counts, scan_passed):
    """
    Save scan results to HTML and JSON files.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}STEP 7: Saving Reports...")
    print("=" * 60)
    
    # Create reports directory if it doesn't exist
    report_dir = Path(config.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save HTML report
    try:
        html_report = zap.core.htmlreport()
        filename = report_dir / f"zap_report_{timestamp}.html"
        with open(filename, 'w') as f:
            f.write(html_report)
        print(f"{Fore.GREEN}✓ HTML report saved: {filename}")
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to save HTML report: {e}")
    
    # Save detailed JSON report
    try:
        filename = report_dir / f"zap_report_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"{Fore.GREEN}✓ JSON report saved: {filename}")
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to save JSON report: {e}")
    
    # Save summary JSON
    try:
        summary = {
            'timestamp': timestamp,
            'target_url': config.target_url,
            'scan_type': config.scan_type,
            'total_alerts': len(alerts),
            'risk_counts': risk_counts,
            'thresholds': {
                'max_high': config.max_high,
                'max_medium': config.max_medium,
                'max_low': config.max_low
            },
            'passed': scan_passed,
            'high_risk_alerts': [
                {
                    'name': alert['alert'],
                    'url': alert['url'],
                    'description': alert['description'][:200]
                }
                for alert in alerts if alert.get('risk') == 'High'
            ]
        }
        
        filename = report_dir / f"zap_summary_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"{Fore.GREEN}✓ Summary saved: {filename}")
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to save summary: {e}")

# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    """
    Main function that orchestrates the entire scan.
    """
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}{Style.BRIGHT}CONFIGURABLE ZAP SECURITY SCANNER - v2.0")
    print("=" * 60)
    
    try:
        # Load and validate configuration
        config = ScanConfig()
        config.display()
        
        # Get scan type configuration
        scan_type_config = ScanTypeConfig.get(config.scan_type)
        print(f"\n{Fore.CYAN}Scan Type: {scan_type_config['name']}")
        print(f"  {scan_type_config['description']}")
        print(f"  Estimated duration: {scan_type_config['duration_estimate']}")
        
        # Step 1: Wait for ZAP
        if not wait_for_zap(config):
            print(f"\n{Fore.RED}❌ Error: ZAP is not available")
            sys.exit(2)
        
        # Step 2: Connect to ZAP
        zap = connect_to_zap(config)
        
        # Step 3: Access target
        access_target(zap, config)
        
        # Step 4: Spider scan
        urls = run_spider_scan(zap, config, scan_type_config)
        
        # Step 5: Active scan (if enabled for this scan type)
        run_active_scan(zap, config, scan_type_config)
        
        # Step 6: Get results
        alerts = get_alerts(zap, config)
        risk_counts = analyze_alerts(alerts)
        scan_passed = display_results(alerts, risk_counts, config)
        
        # Step 7: Save reports
        save_reports(zap, alerts, config, risk_counts, scan_passed)
        
        print(f"\n{Fore.CYAN}Reports saved to {Fore.WHITE}{config.report_dir}/")
        
        # Exit with appropriate code
        if scan_passed:
            print(f"\n{Fore.GREEN}✅ Exiting with code 0 (SUCCESS)")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}❌ Exiting with code 1 (FAILURE)")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Scan interrupted by user")
        sys.exit(130)  # Standard Unix exit code for SIGINT
    except Exception as e:
        print(f"\n\n{Fore.RED}❌ Error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()