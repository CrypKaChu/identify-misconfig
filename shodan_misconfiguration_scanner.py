#!/usr/bin/env python3
"""
Shodan Misconfiguration Scanner
Author:
Description: Scan for publicly accessible databases and file servers with open authentication
using the Shodan API.

DISCLAIMER: This script is for educational and authorized security testing purposes only.
Only use this tool on systems you own or have explicit permission to test.
"""

import shodan
import sys
import argparse
from typing import List, Dict
import json
from datetime import datetime


class ShodanScanner:
    """Scanner class to identify misconfigured services using Shodan API"""

    def __init__(self, api_key: str):
        """
        Initialize Shodan scanner with API key

        Args:
            api_key: Your Shodan API key
        """
        self.api = shodan.Shodan(api_key)

        # Define search queries for different vulnerable services
        self.database_queries = {
            'mongodb': 'product:MongoDB port:27017 -authentication',
            'mongodb_alt': '"MongoDB Server Information" port:27017 -authentication',
            'mongodb_unauth': 'port:27017 -authentication "MongoDB"',
            'elasticsearch': 'port:9200 product:Elastic',
            'elasticsearch_indices': 'port:9200 all:"elastic indices"',
            'elasticsearch_unauth': 'port:9200 -authentication product:Elastic',
            'redis': 'product:Redis port:6379',
            'redis_unauth': 'port:6379 -authentication',
            'mysql': 'product:MySQL port:3306',
            'mysql_unauth': 'port:3306 -authentication product:MySQL',
            'postgresql': 'product:PostgreSQL port:5432',
            'postgresql_unauth': 'port:5432 -authentication product:PostgreSQL',
            'memcached': 'port:11211 product:memcached',
            'memcached_unauth': 'port:11211 -authentication product:memcached',
            'couchdb': 'port:5984 product:couchdb',
            'couchdb_unauth': 'port:5984 -authentication product:couchdb',
            'cassandra': 'port:9042 product:Cassandra',
            'cassandra_unauth': 'port:9042 -authentication product:Cassandra'
        }

        self.fileserver_queries = {
            'ftp': 'port:21 product:FTP',
            'ftp_anonymous': 'port:21 "Anonymous access granted"',
            'smb': 'port:445 product:Samba',
            'smb_open': 'port:445 "authentication disabled"',
            'nfs': 'port:2049 product:nfs',
            'rsync': 'port:873 product:rsync',
            'webdav': 'port:80 "WebDAV"',
            'tftp': 'port:69 product:tftp'
        }

        # Vulnerability database mapping products/versions to known CVEs
        self.vulnerability_db = {
            'MongoDB': {
                '2.6.x': ['CVE-2014-3956', 'CVE-2015-4410'],
                '3.0.x': ['CVE-2015-4410', 'CVE-2016-6494'],
                '3.2.x': ['CVE-2016-6494', 'CVE-2017-7922'],
                '3.4.x': ['CVE-2017-7922', 'CVE-2018-1000053'],
                '3.6.x': ['CVE-2018-1000053', 'CVE-2019-2391'],
                '4.0.x': ['CVE-2019-2391', 'CVE-2020-7928'],
                '4.2.x': ['CVE-2020-7928', 'CVE-2021-20330'],
                '4.4.x': ['CVE-2021-20330', 'CVE-2022-31023'],
                '5.0.x': ['CVE-2022-31023', 'CVE-2023-31022'],
                'default': ['CVE-2014-3956', 'CVE-2015-4410', 'CVE-2016-6494']
            },
            'Redis': {
                '2.8.x': ['CVE-2015-4335', 'CVE-2015-8080'],
                '3.0.x': ['CVE-2015-8080', 'CVE-2016-8339'],
                '3.2.x': ['CVE-2016-8339', 'CVE-2017-7525'],
                '4.0.x': ['CVE-2017-7525', 'CVE-2018-11218'],
                '5.0.x': ['CVE-2018-11218', 'CVE-2019-10192'],
                '6.0.x': ['CVE-2019-10192', 'CVE-2021-29477'],
                '6.2.x': ['CVE-2021-29477', 'CVE-2022-24736'],
                '7.0.x': ['CVE-2022-24736', 'CVE-2023-28858'],
                'default': ['CVE-2015-4335', 'CVE-2015-8080', 'CVE-2016-8339']
            },
            'Elasticsearch': {
                '1.x': ['CVE-2014-3120', 'CVE-2015-1427'],
                '2.x': ['CVE-2015-1427', 'CVE-2015-3337'],
                '5.x': ['CVE-2015-3337', 'CVE-2017-8464'],
                '6.x': ['CVE-2017-8464', 'CVE-2019-7611'],
                '7.x': ['CVE-2019-7611', 'CVE-2021-22145'],
                '8.x': ['CVE-2021-22145', 'CVE-2022-23709'],
                'default': ['CVE-2014-3120', 'CVE-2015-1427', 'CVE-2015-3337']
            },
            'MySQL': {
                '5.5.x': ['CVE-2012-2122', 'CVE-2013-1492'],
                '5.6.x': ['CVE-2013-1492', 'CVE-2016-6662'],
                '5.7.x': ['CVE-2016-6662', 'CVE-2018-3058'],
                '8.0.x': ['CVE-2018-3058', 'CVE-2021-3711'],
                'default': ['CVE-2012-2122', 'CVE-2013-1492', 'CVE-2016-6662']
            },
            'PostgreSQL': {
                '9.0.x': ['CVE-2010-4015', 'CVE-2011-2483'],
                '9.1.x': ['CVE-2011-2483', 'CVE-2012-3488'],
                '9.2.x': ['CVE-2012-3488', 'CVE-2013-1899'],
                '9.3.x': ['CVE-2013-1899', 'CVE-2014-0067'],
                '9.4.x': ['CVE-2014-0067', 'CVE-2015-3167'],
                '9.5.x': ['CVE-2015-3167', 'CVE-2016-5423'],
                '9.6.x': ['CVE-2016-5423', 'CVE-2017-8804'],
                '10.x': ['CVE-2017-8804', 'CVE-2018-1058'],
                '11.x': ['CVE-2018-1058', 'CVE-2019-10208'],
                '12.x': ['CVE-2019-10208', 'CVE-2020-25695'],
                '13.x': ['CVE-2020-25695', 'CVE-2021-32027'],
                '14.x': ['CVE-2021-32027', 'CVE-2022-1552'],
                '15.x': ['CVE-2022-1552', 'CVE-2023-2454'],
                'default': ['CVE-2010-4015', 'CVE-2011-2483', 'CVE-2012-3488']
            }
        }

    def parse_banner(self, banner: str, product: str) -> Dict:
        """
        Parse service banner to extract security indicators
        
        Args:
            banner: Service banner text
            product: Database product name
            
        Returns:
            Dictionary with parsed security information
        """
        banner_lower = banner.lower()
        
        # Authentication indicators
        auth_indicators = {
            'required': ['authentication required', 'login required', 'auth required', 'password required'],
            'optional': ['authentication optional', 'auth optional'],
            'none': ['no authentication', 'authentication disabled', 'anonymous access', 'public access'],
            'error': ['authentication failed', 'login failed', 'access denied', 'unauthorized']
        }
        
        # Encryption indicators
        encryption_indicators = {
            'enabled': ['ssl', 'tls', 'encrypted', 'secure connection'],
            'disabled': ['unencrypted', 'plain text', 'no encryption']
        }
        
        # Default configuration indicators
        default_config_indicators = [
            'default password', 'admin:admin', 'root:root', 'user:user',
            'default user', 'test:test', 'demo:demo', 'guest:guest',
            'welcome', 'default configuration', 'initial setup'
        ]
        
        # Determine authentication status
        auth_status = 'unknown'
        for status, indicators in auth_indicators.items():
            if any(indicator in banner_lower for indicator in indicators):
                auth_status = status
                break
        
        # Determine encryption status
        encryption_status = 'unknown'
        for status, indicators in encryption_indicators.items():
            if any(indicator in banner_lower for indicator in indicators):
                encryption_status = status
                break
        
        # Check for default configuration
        default_creds_likely = any(indicator in banner_lower for indicator in default_config_indicators)
        
        return {
            'authentication_status': auth_status,
            'encryption_status': encryption_status,
            'default_creds_likely': default_creds_likely,
            'banner_analysis': {
                'length': len(banner),
                'has_errors': any(error in banner_lower for error in auth_indicators['error']),
                'has_welcome': 'welcome' in banner_lower,
                'has_version': any(char.isdigit() for char in banner)
            }
        }

    def get_vulnerabilities(self, product: str, version: str) -> List[str]:
        """
        Get known vulnerabilities for a product/version combination
        
        Args:
            product: Database product name
            version: Version string
            
        Returns:
            List of CVE identifiers
        """
        if product not in self.vulnerability_db:
            return []
        
        product_vulns = self.vulnerability_db[product]
        
        # Try to match version
        if version and version != 'N/A':
            # Extract major.minor version
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major_minor = f"{version_parts[0]}.{version_parts[1]}.x"
                if major_minor in product_vulns:
                    return product_vulns[major_minor]
        
        # Return default vulnerabilities if no specific match
        return product_vulns.get('default', [])

    def calculate_risk_score(self, host_info: Dict) -> int:
        """
        Calculate risk score based on detected misconfigurations
        
        Args:
            host_info: Host information dictionary
            
        Returns:
            Risk score (0-10)
        """
        score = 0
        
        # No authentication: +5 points
        if host_info.get('authentication_status') == 'none':
            score += 5
        elif host_info.get('authentication_status') == 'optional':
            score += 3
        
        # Known vulnerable version: +3 points
        if host_info.get('vulnerabilities'):
            score += 3
        
        # Default configuration detected: +2 points
        if host_info.get('default_creds_likely'):
            score += 2
        
        # No encryption: +2 points
        if host_info.get('encryption_status') == 'disabled':
            score += 2
        
        # Public cloud exposure: +1 point
        cloud_indicators = ['amazon', 'aws', 'google', 'microsoft', 'azure', 'cloud']
        if any(cloud in host_info.get('org', '').lower() for cloud in cloud_indicators):
            score += 1
        
        # High-risk organizations: +1 point
        high_risk_orgs = ['government', 'bank', 'financial', 'health', 'medical']
        if any(risk_org in host_info.get('org', '').lower() for risk_org in high_risk_orgs):
            score += 1
        
        return min(score, 10)  # Cap at 10

    def analyze_misconfiguration(self, host_info: Dict) -> Dict:
        """
        Analyze host for misconfigurations and security issues
        
        Args:
            host_info: Basic host information from Shodan
            
        Returns:
            Enhanced host information with security analysis
        """
        # Parse banner for security indicators
        banner_analysis = self.parse_banner(host_info.get('banner', ''), host_info.get('product', ''))
        
        # Get vulnerabilities based on product and version
        vulnerabilities = self.get_vulnerabilities(host_info.get('product', ''), host_info.get('version', ''))
        
        # Calculate risk score
        risk_score = self.calculate_risk_score({
            **host_info,
            **banner_analysis,
            'vulnerabilities': vulnerabilities
        })
        
        # Identify misconfiguration indicators
        misconfig_indicators = []
        
        if banner_analysis['authentication_status'] == 'none':
            misconfig_indicators.append('No authentication required')
        elif banner_analysis['authentication_status'] == 'optional':
            misconfig_indicators.append('Authentication optional')
        
        if banner_analysis['encryption_status'] == 'disabled':
            misconfig_indicators.append('No encryption detected')
        
        if banner_analysis['default_creds_likely']:
            misconfig_indicators.append('Default credentials likely')
        
        if vulnerabilities:
            misconfig_indicators.append(f'{len(vulnerabilities)} known vulnerabilities')
        
        if banner_analysis['banner_analysis']['has_errors']:
            misconfig_indicators.append('Error messages in banner')
        
        # Enhance host info with security analysis
        enhanced_info = {
            **host_info,
            **banner_analysis,
            'vulnerabilities': vulnerabilities,
            'misconfiguration_score': risk_score,
            'misconfiguration_indicators': misconfig_indicators,
            'risk_level': 'HIGH' if risk_score >= 7 else 'MEDIUM' if risk_score >= 4 else 'LOW'
        }
        
        return enhanced_info

    def prompt_scan_options(self) -> Dict:
        """
        Interactively prompt user for scan configuration options
        
        Returns:
            Dictionary with scan configuration options
        """
        print("\n" + "="*60)
        print("SCAN CONFIGURATION")
        print("="*60)
        
        # Country filter
        print("\n[?] Enter country filter (leave blank for all countries):")
        print("    Examples: US, UK, IN, DE, FR, CA, AU")
        country = input("    Country code: ").strip().upper()
        
        # Product selection
        print("\n[?] Select database products to scan:")
        print("    Available databases: mongodb, redis, elasticsearch, mysql, postgresql, memcached, couchdb, cassandra")
        print("    Available fileservers: ftp, smb, nfs, rsync, webdav, tftp")
        print("    Options: 'all', 'databases', 'fileservers', or comma-separated list")
        products_input = input("    Products: ").strip().lower()
        
        # Parse product selection
        if products_input == 'all':
            selected_products = 'all'
        elif products_input == 'databases':
            selected_products = 'databases'
        elif products_input == 'fileservers':
            selected_products = 'fileservers'
        else:
            selected_products = [p.strip() for p in products_input.split(',') if p.strip()]
        
        # Per-query limit
        print("\n[?] Maximum results per product query:")
        print("    (Each product type will be limited to this many results)")
        while True:
            try:
                per_query_limit = int(input("    Max per product (default 20): ") or "20")
                if per_query_limit > 0:
                    break
                else:
                    print("    Please enter a positive number.")
            except ValueError:
                print("    Please enter a valid number.")
        
        # Global limit
        print("\n[?] Global maximum results (total across all queries):")
        print("    (Scan will stop when this total is reached)")
        while True:
            try:
                global_limit = int(input("    Global max (default 100): ") or "100")
                if global_limit > 0:
                    break
                else:
                    print("    Please enter a positive number.")
            except ValueError:
                print("    Please enter a valid number.")
        
        return {
            'country': country if country else None,
            'products': selected_products,
            'per_query_limit': per_query_limit,
            'global_limit': global_limit
        }

    def filter_queries_by_products(self, selected_products: str) -> Dict:
        """
        Filter query dictionaries based on user product selection
        
        Args:
            selected_products: Product selection from user input
            
        Returns:
            Dictionary with filtered database and fileserver queries
        """
        filtered_queries = {
            'databases': {},
            'fileservers': {}
        }
        
        if selected_products == 'all':
            filtered_queries['databases'] = self.database_queries.copy()
            filtered_queries['fileservers'] = self.fileserver_queries.copy()
        elif selected_products == 'databases':
            filtered_queries['databases'] = self.database_queries.copy()
        elif selected_products == 'fileservers':
            filtered_queries['fileservers'] = self.fileserver_queries.copy()
        else:
            # Filter by specific products
            for product in selected_products:
                # Check database queries
                for db_name, query in self.database_queries.items():
                    if product in db_name.lower() or product in query.lower():
                        filtered_queries['databases'][db_name] = query
                
                # Check fileserver queries
                for fs_name, query in self.fileserver_queries.items():
                    if product in fs_name.lower() or product in query.lower():
                        filtered_queries['fileservers'][fs_name] = query
        
        return filtered_queries

    def estimate_credits(self, config: Dict, filtered_queries: Dict) -> Dict:
        """
        Estimate Shodan credit usage based on scan configuration
        
        Args:
            config: Scan configuration from user input
            filtered_queries: Filtered query dictionaries
            
        Returns:
            Dictionary with credit estimation details
        """
        total_queries = 0
        estimated_results = 0
        
        # Count database queries
        if filtered_queries['databases']:
            total_queries += len(filtered_queries['databases'])
            estimated_results += len(filtered_queries['databases']) * config['per_query_limit']
        
        # Count fileserver queries
        if filtered_queries['fileservers']:
            total_queries += len(filtered_queries['fileservers'])
            estimated_results += len(filtered_queries['fileservers']) * config['per_query_limit']
        
        # Apply global limit
        estimated_results = min(estimated_results, config['global_limit'])
        
        # Estimate credits (1 credit per 100 results as baseline)
        estimated_credits = max(1, estimated_results // 100)
        
        return {
            'total_queries': total_queries,
            'estimated_results': estimated_results,
            'estimated_credits': estimated_credits,
            'per_query_limit': config['per_query_limit'],
            'global_limit': config['global_limit']
        }

    def confirm_scan(self, config: Dict, filtered_queries: Dict, credit_estimate: Dict) -> bool:
        """
        Display scan summary and ask for user confirmation
        
        Args:
            config: Scan configuration
            filtered_queries: Filtered query dictionaries
            credit_estimate: Credit estimation details
            
        Returns:
            True if user confirms, False otherwise
        """
        print("\n" + "="*60)
        print("SCAN PLAN SUMMARY")
        print("="*60)
        
        print(f"Country Filter: {config['country'] or 'All countries'}")
        print(f"Selected Products: {config['products']}")
        print(f"Per-query Limit: {config['per_query_limit']} results")
        print(f"Global Limit: {config['global_limit']} results")
        print()
        
        print("Query Breakdown:")
        if filtered_queries['databases']:
            print(f"  Database queries: {len(filtered_queries['databases'])}")
            for db_name in list(filtered_queries['databases'].keys())[:5]:
                print(f"    - {db_name}")
            if len(filtered_queries['databases']) > 5:
                print(f"    ... and {len(filtered_queries['databases']) - 5} more")
        
        if filtered_queries['fileservers']:
            print(f"  Fileserver queries: {len(filtered_queries['fileservers'])}")
            for fs_name in list(filtered_queries['fileservers'].keys())[:5]:
                print(f"    - {fs_name}")
            if len(filtered_queries['fileservers']) > 5:
                print(f"    ... and {len(filtered_queries['fileservers']) - 5} more")
        
        print()
        print("Credit Estimation:")
        print(f"  Total queries: {credit_estimate['total_queries']}")
        print(f"  Estimated results: {credit_estimate['estimated_results']}")
        print(f"  Estimated credits: {credit_estimate['estimated_credits']}")
        print()
        
        while True:
            confirm = input("[?] Proceed with scan? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                return True
            elif confirm in ['n', 'no']:
                return False
            else:
                print("Please enter 'y' or 'n'.")

    def search(self, query: str, max_results: int = 100) -> List[Dict]:
        """
        Execute a Shodan search query

        Args:
            query: Shodan search query string
            max_results: Maximum number of results to return

        Returns:
            List of result dictionaries
        """
        results = []
        try:
            # Search Shodan
            search_results = self.api.search(query, limit=max_results)

            print(f"[+] Found {search_results['total']} total results for query: {query}")
            print(f"[+] Retrieving up to {max_results} results...\n")

            for result in search_results['matches']:
                host_info = {
                    'ip': result.get('ip_str', 'N/A'),
                    'port': result.get('port', 'N/A'),
                    'org': result.get('org', 'N/A'),
                    'hostnames': result.get('hostnames', []),
                    'country': result.get('location', {}).get('country_name', 'N/A'),
                    'city': result.get('location', {}).get('city', 'N/A'),
                    'product': result.get('product', 'N/A'),
                    'version': result.get('version', 'N/A'),
                    'os': result.get('os', 'N/A'),
                    'timestamp': result.get('timestamp', 'N/A'),
                    'banner': result.get('data', '')[:200]  # First 200 chars of banner
                }
                
                # Analyze for misconfigurations
                enhanced_info = self.analyze_misconfiguration(host_info)
                results.append(enhanced_info)

        except shodan.APIError as e:
            print(f"[-] Error: {e}")

        return results

    def scan_databases(self, max_results: int = 100, filtered_queries: Dict = None, 
                       global_limit: int = None, country: str = None) -> Dict:
        """
        Scan for misconfigured databases with dual limit support

        Args:
            max_results: Maximum results per query
            filtered_queries: Filtered database queries to use
            global_limit: Global maximum results across all queries
            country: Country filter to apply

        Returns:
            Dictionary of database types and their results
        """
        print("="*80)
        print("SCANNING FOR MISCONFIGURED DATABASES")
        print("="*80)

        all_results = {}
        total_results = 0
        
        # Use filtered queries if provided, otherwise use all database queries
        queries_to_use = filtered_queries if filtered_queries else self.database_queries
        
        for db_name, query in queries_to_use.items():
            # Apply country filter if specified
            if country:
                query += f' country:{country}'
            
            print(f"\n[*] Searching for: {db_name}")
            print(f"[*] Query: {query}")
            if global_limit:
                remaining = global_limit - total_results
                print(f"[*] Remaining global quota: {remaining}")
            print()

            # Check if we've hit the global limit
            if global_limit and total_results >= global_limit:
                print(f"[!] Global limit of {global_limit} reached. Stopping scan.")
                break
            
            # Calculate how many results to request for this query
            query_limit = max_results
            if global_limit:
                query_limit = min(max_results, global_limit - total_results)
            
            if query_limit <= 0:
                print(f"[!] No remaining quota for {db_name}")
                break

            results = self.search(query, query_limit)
            all_results[db_name] = results
            total_results += len(results)
            
            print(f"[+] Found {len(results)} results for {db_name} (Total: {total_results})")

            # Display results with security analysis
            for idx, host in enumerate(results[:10], 1):  # Show first 10
                print(f"  [{idx}] {host['ip']}:{host['port']} [{host.get('risk_level', 'UNKNOWN')}]")
                print(f"      Organization: {host['org']}")
                print(f"      Location: {host['city']}, {host['country']}")
                print(f"      Product: {host['product']} {host['version']}")
                print(f"      Risk Score: {host.get('misconfiguration_score', 0)}/10")
                print(f"      Auth Status: {host.get('authentication_status', 'unknown')}")
                print(f"      Encryption: {host.get('encryption_status', 'unknown')}")
                
                if host.get('misconfiguration_indicators'):
                    print(f"      Issues: {', '.join(host['misconfiguration_indicators'])}")
                
                if host.get('vulnerabilities'):
                    vulns = host['vulnerabilities'][:3]  # Show first 3 CVEs
                    print(f"      Vulnerabilities: {', '.join(vulns)}")
                    if len(host['vulnerabilities']) > 3:
                        print(f"      ... and {len(host['vulnerabilities']) - 3} more")
                
                print()

        return all_results

    def scan_fileservers(self, max_results: int = 100, filtered_queries: Dict = None,
                         global_limit: int = None, country: str = None) -> Dict:
        """
        Scan for misconfigured file servers with dual limit support

        Args:
            max_results: Maximum results per query
            filtered_queries: Filtered fileserver queries to use
            global_limit: Global maximum results across all queries
            country: Country filter to apply

        Returns:
            Dictionary of file server types and their results
        """
        print("\n" + "="*80)
        print("SCANNING FOR MISCONFIGURED FILE SERVERS")
        print("="*80)

        all_results = {}
        total_results = 0
        
        # Use filtered queries if provided, otherwise use all fileserver queries
        queries_to_use = filtered_queries if filtered_queries else self.fileserver_queries
        
        for fs_name, query in queries_to_use.items():
            # Apply country filter if specified
            if country:
                query += f' country:{country}'
            
            print(f"\n[*] Searching for: {fs_name}")
            print(f"[*] Query: {query}")
            if global_limit:
                remaining = global_limit - total_results
                print(f"[*] Remaining global quota: {remaining}")
            print()

            # Check if we've hit the global limit
            if global_limit and total_results >= global_limit:
                print(f"[!] Global limit of {global_limit} reached. Stopping scan.")
                break
            
            # Calculate how many results to request for this query
            query_limit = max_results
            if global_limit:
                query_limit = min(max_results, global_limit - total_results)
            
            if query_limit <= 0:
                print(f"[!] No remaining quota for {fs_name}")
                break

            results = self.search(query, query_limit)
            all_results[fs_name] = results
            total_results += len(results)
            
            print(f"[+] Found {len(results)} results for {fs_name} (Total: {total_results})")

            # Display results with security analysis
            for idx, host in enumerate(results[:10], 1):  # Show first 10
                print(f"  [{idx}] {host['ip']}:{host['port']} [{host.get('risk_level', 'UNKNOWN')}]")
                print(f"      Organization: {host['org']}")
                print(f"      Location: {host['city']}, {host['country']}")
                print(f"      Product: {host['product']} {host['version']}")
                print(f"      Risk Score: {host.get('misconfiguration_score', 0)}/10")
                print(f"      Auth Status: {host.get('authentication_status', 'unknown')}")
                print(f"      Encryption: {host.get('encryption_status', 'unknown')}")
                
                if host.get('misconfiguration_indicators'):
                    print(f"      Issues: {', '.join(host['misconfiguration_indicators'])}")
                
                if host.get('vulnerabilities'):
                    vulns = host['vulnerabilities'][:3]  # Show first 3 CVEs
                    print(f"      Vulnerabilities: {', '.join(vulns)}")
                    if len(host['vulnerabilities']) > 3:
                        print(f"      ... and {len(host['vulnerabilities']) - 3} more")
                
                print()

        return all_results

    def scan_all(self, max_results: int = 100, filtered_queries: Dict = None,
                 global_limit: int = None, country: str = None) -> Dict:
        """
        Scan for both databases and file servers with dual limit support

        Args:
            max_results: Maximum results per query
            filtered_queries: Filtered query dictionaries
            global_limit: Global maximum results across all queries
            country: Country filter to apply

        Returns:
            Dictionary containing all results
        """
        all_results = {
            'databases': self.scan_databases(
                max_results, 
                filtered_queries.get('databases') if filtered_queries else None,
                global_limit, 
                country
            ),
            'fileservers': self.scan_fileservers(
                max_results,
                filtered_queries.get('fileservers') if filtered_queries else None,
                global_limit,
                country
            ),
            'timestamp': datetime.now().isoformat()
        }

        return all_results

    def generate_summary(self, results: Dict) -> None:
        """
        Generate and display summary statistics for the scan results
        
        Args:
            results: Complete scan results dictionary
        """
        print("\n" + "="*80)
        print("MISCONFIGURATION SCAN SUMMARY")
        print("="*80)
        
        total_hosts = 0
        high_risk_hosts = 0
        medium_risk_hosts = 0
        low_risk_hosts = 0
        no_auth_hosts = 0
        vulnerable_hosts = 0
        default_creds_hosts = 0
        
        # Analyze database results
        if 'databases' in results:
            for db_type, hosts in results['databases'].items():
                for host in hosts:
                    total_hosts += 1
                    
                    risk_level = host.get('risk_level', 'UNKNOWN')
                    if risk_level == 'HIGH':
                        high_risk_hosts += 1
                    elif risk_level == 'MEDIUM':
                        medium_risk_hosts += 1
                    else:
                        low_risk_hosts += 1
                    
                    if host.get('authentication_status') == 'none':
                        no_auth_hosts += 1
                    
                    if host.get('vulnerabilities'):
                        vulnerable_hosts += 1
                    
                    if host.get('default_creds_likely'):
                        default_creds_hosts += 1
        
        # Analyze file server results
        if 'fileservers' in results:
            for fs_type, hosts in results['fileservers'].items():
                for host in hosts:
                    total_hosts += 1
                    
                    risk_level = host.get('risk_level', 'UNKNOWN')
                    if risk_level == 'HIGH':
                        high_risk_hosts += 1
                    elif risk_level == 'MEDIUM':
                        medium_risk_hosts += 1
                    else:
                        low_risk_hosts += 1
                    
                    if host.get('authentication_status') == 'none':
                        no_auth_hosts += 1
                    
                    if host.get('vulnerabilities'):
                        vulnerable_hosts += 1
                    
                    if host.get('default_creds_likely'):
                        default_creds_hosts += 1
        
        # Display summary
        print(f"Total hosts scanned: {total_hosts}")
        print(f"High risk hosts: {high_risk_hosts} ({high_risk_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "High risk hosts: 0")
        print(f"Medium risk hosts: {medium_risk_hosts} ({medium_risk_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "Medium risk hosts: 0")
        print(f"Low risk hosts: {low_risk_hosts} ({low_risk_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "Low risk hosts: 0")
        print()
        print("Security Issues:")
        print(f"  - No authentication required: {no_auth_hosts} ({no_auth_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "  - No authentication required: 0")
        print(f"  - Known vulnerabilities: {vulnerable_hosts} ({vulnerable_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "  - Known vulnerabilities: 0")
        print(f"  - Default credentials likely: {default_creds_hosts} ({default_creds_hosts/total_hosts*100:.1f}%)" if total_hosts > 0 else "  - Default credentials likely: 0")
        
        if high_risk_hosts > 0:
            print(f"\n[!] WARNING: {high_risk_hosts} high-risk misconfigurations detected!")
            print("    These require immediate attention.")

    def export_results(self, results: Dict, filename: str = 'shodan_results.json'):
        """
        Export results to JSON file

        Args:
            results: Results dictionary to export
            filename: Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n[+] Results exported to {filename}")
        except Exception as e:
            print(f"[-] Error exporting results: {e}")

    def get_host_info(self, ip: str):
        """
        Get detailed information about a specific host

        Args:
            ip: IP address to lookup
        """
        try:
            host = self.api.host(ip)

            print(f"\n{'='*80}")
            print(f"DETAILED HOST INFORMATION: {ip}")
            print('='*80)
            print(f"Organization: {host.get('org', 'N/A')}")
            print(f"Operating System: {host.get('os', 'N/A')}")
            print(f"Country: {host.get('country_name', 'N/A')}")
            print(f"City: {host.get('city', 'N/A')}")
            print(f"Hostnames: {', '.join(host.get('hostnames', []))}")

            print(f"\nOpen Ports:")
            for item in host['data']:
                print(f"  - Port {item['port']}: {item.get('product', 'Unknown')} "
                      f"{item.get('version', '')}")

        except shodan.APIError as e:
            print(f"[-] Error: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Shodan Misconfiguration Scanner - Find publicly accessible databases and file servers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended for credit control)
  python shodan_scanner.py --api-key YOUR_API_KEY --interactive

  # Scan for databases only
  python shodan_scanner.py --api-key YOUR_API_KEY --databases

  # Scan for file servers only  
  python shodan_scanner.py --api-key YOUR_API_KEY --fileservers

  # Scan for both and export results
  python shodan_scanner.py --api-key YOUR_API_KEY --all --export results.json

  # Get info about specific IP
  python shodan_scanner.py --api-key YOUR_API_KEY --host 1.2.3.4
        """
    )

    parser.add_argument('--api-key', required=True, help='Your Shodan API key')
    parser.add_argument('--databases', action='store_true', help='Scan for misconfigured databases')
    parser.add_argument('--fileservers', action='store_true', help='Scan for misconfigured file servers')
    parser.add_argument('--all', action='store_true', help='Scan for both databases and file servers')
    parser.add_argument('--interactive', action='store_true', help='Use interactive mode for scan configuration')
    parser.add_argument('--host', help='Get detailed info about a specific IP address')
    parser.add_argument('--max-results', type=int, default=100, help='Maximum results per query (default: 100)')
    parser.add_argument('--export', help='Export results to JSON file')
    parser.add_argument('--country', help='Filter results by country code (e.g., US, UK, IN)')

    args = parser.parse_args()

    # Initialize scanner
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         Shodan Misconfiguration Scanner v1.0                  ║
    ║         Find Open Databases & File Servers                    ║
    ╚═══════════════════════════════════════════════════════════════╝

    [!] DISCLAIMER: Use only on systems you own or have permission to test
    """)

    scanner = ShodanScanner(args.api_key)

    # Execute requested scans
    results = None

    if args.host:
        scanner.get_host_info(args.host)
    elif args.interactive:
        # Interactive mode - prompt for configuration
        config = scanner.prompt_scan_options()
        filtered_queries = scanner.filter_queries_by_products(config['products'])
        credit_estimate = scanner.estimate_credits(config, filtered_queries)
        
        if not scanner.confirm_scan(config, filtered_queries, credit_estimate):
            print("\n[!] Scan cancelled by user.")
            return
        
        # Execute scan with interactive configuration
        if config['products'] == 'all' or (config['products'] == 'databases' and config['products'] == 'fileservers'):
            results = scanner.scan_all(
                config['per_query_limit'],
                filtered_queries,
                config['global_limit'],
                config['country']
            )
        elif config['products'] == 'databases':
            results = {'databases': scanner.scan_databases(
                config['per_query_limit'],
                filtered_queries.get('databases'),
                config['global_limit'],
                config['country']
            )}
        elif config['products'] == 'fileservers':
            results = {'fileservers': scanner.scan_fileservers(
                config['per_query_limit'],
                filtered_queries.get('fileservers'),
                config['global_limit'],
                config['country']
            )}
        else:
            # Mixed selection - scan both with filtered queries
            results = scanner.scan_all(
                config['per_query_limit'],
                filtered_queries,
                config['global_limit'],
                config['country']
            )
    elif args.all:
        # Apply country filter if specified
        country_filter = args.country
        results = scanner.scan_all(args.max_results, country=country_filter)
    elif args.databases:
        # Apply country filter if specified
        country_filter = args.country
        results = {'databases': scanner.scan_databases(args.max_results, country=country_filter)}
    elif args.fileservers:
        # Apply country filter if specified
        country_filter = args.country
        results = {'fileservers': scanner.scan_fileservers(args.max_results, country=country_filter)}
    else:
        parser.print_help()
        return

    # Generate summary if we have results
    if results:
        scanner.generate_summary(results)
    
    # Export results if requested
    if args.export and results:
        scanner.export_results(results, args.export)

    print("\n[+] Scan complete!")
    print("\n[!] Remember to report any findings responsibly!")


if __name__ == '__main__':
    main()
