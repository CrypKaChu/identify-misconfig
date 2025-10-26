#!/usr/bin/env python3
"""
Enhanced Misconfiguration Scanner v2.0

A comprehensive security scanner for finding publicly accessible databases and file servers
with advanced filtering, caching, and output capabilities.

Author: Security Research Team
License: Educational/Research Use Only
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from shodan import Shodan
from censys.search import CensysHosts
from dotenv import load_dotenv

# Import our utility modules
from utils import DataFilter, CacheManager, OutputFormatter, InputMenu, ShodanScanner

# Load environment variables from .env file
load_dotenv('.env_file')

# Unified query configuration for both Shodan and Censys
SCAN_CONFIG = {
    "scope": {
        "shodan": 'org:"Acme Corp"',  # or net:x.x.x.x/yy or asn:ASXXX
        "censys": 'autonomous_system.organization: "Acme Corp"'  # or ip:x.x.x.x/yy
    },
    "services": {
        "databases": {
            "elasticsearch": {
                "port": 9200,
                "shodan_query": "port:9200 product:elastic",
                "censys_query": "services.port: 9200 AND services.service_name: HTTP",
                "risk": "high",
                "description": "Exposed Elasticsearch cluster"
            },
            "mongodb": {
                "port": 27017,
                "shodan_query": "port:27017 product:mongodb",
                "censys_query": "services.port: 27017",
                "risk": "critical",
                "description": "Unauthenticated MongoDB instance"
            },
            "redis": {
                "port": 6379,
                "shodan_query": "port:6379 product:redis",
                "censys_query": "services.port: 6379",
                "risk": "high",
                "description": "Redis key-value store"
            },
            "mysql": {
                "port": 3306,
                "shodan_query": "port:3306 product:mysql",
                "censys_query": "services.port: 3306",
                "risk": "high",
                "description": "MySQL database server"
            },
            "postgresql": {
                "port": 5432,
                "shodan_query": "port:5432 product:postgresql",
                "censys_query": "services.port: 5432",
                "risk": "high",
                "description": "PostgreSQL database server"
            },
            "mssql": {
                "port": 1433,
                "shodan_query": "port:1433 product:\"microsoft sql\"",
                "censys_query": "services.port: 1433",
                "risk": "high",
                "description": "Microsoft SQL Server"
            },
            "cassandra": {
                "port": 9042,
                "shodan_query": "port:9042 product:cassandra",
                "censys_query": "services.port: 9042",
                "risk": "high",
                "description": "Apache Cassandra cluster"
            }
        },
        "file_servers": {
            "ftp": {
                "port": 21,
                "shodan_query": "port:21 product:ftp",
                "censys_query": "services.port: 21 AND services.service_name: FTP",
                "risk": "medium",
                "description": "FTP file server"
            },
            "smb": {
                "port": 445,
                "shodan_query": "port:445",
                "censys_query": "services.port: 445",
                "risk": "high",
                "description": "SMB/CIFS file share"
            },
            "nfs": {
                "port": 2049,
                "shodan_query": "port:2049 product:nfs",
                "censys_query": "services.port: 2049",
                "risk": "medium",
                "description": "Network File System"
            },
            "rsync": {
                "port": 873,
                "shodan_query": "port:873 product:rsync",
                "censys_query": "services.port: 873",
                "risk": "medium",
                "description": "Rsync file synchronization"
            }
        }
    }
}

# --- API Keys ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY") or "YOUR_SHODAN_API_KEY_HERE"
CENSYS_API_ID = os.getenv("CENSYS_API_ID") or "YOUR_CENSYS_API_ID_HERE"
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET") or "YOUR_CENSYS_SECRET_KEY_HERE"


def initialise_scanners():
    """
    Initialises and returns the Shodan and Censys API clients.
    Handles basic error checking for API keys.
    """
    shodan_api = None
    censys_h = None

    # Initialize Shodan API
    try:
        if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
            print("❌ SHODAN_API_KEY is not set")
        else:
            shodan_api = Shodan(SHODAN_API_KEY)
            shodan_api.info()
            print(f"✅ Shodan API is working. Key starts with: {SHODAN_API_KEY[:4]}...")
    except Exception as e:
        print(f"❌ Shodan API Error: {e}")
        shodan_api = None

    # Initialize Censys API
    try:
        if CENSYS_API_SECRET == "YOUR_CENSYS_SECRET_KEY_HERE":
            print("❌ CENSYS_API_SECRET is not set")
        else:
            censys_h = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)
            print(f"✅ Censys API is working. Key starts with: {CENSYS_API_SECRET[:4]}...")
    except Exception as e:
        print(f"❌ Censys API Error: {e}")
        censys_h = None

    return shodan_api, censys_h


def build_query_from_config(config: Dict[str, Any], shodan_scanner: ShodanScanner = None) -> Dict[str, str]:
    """
    Build search queries based on user configuration with enhanced query selection.
    
    Args:
        config: User configuration dictionary
        shodan_scanner: ShodanScanner instance for detailed queries
        
    Returns:
        Dictionary with Shodan and Censys queries
    """
    input_type = config.get('input_type', 'Domain')
    target = config.get('target', '')
    service_type = config.get('service_type', 'All services')
    
    queries = {
        'shodan': '',
        'censys': ''
    }
    
    # Handle wider scan case specially
    if input_type == 'Wider Scan (by country + product)':
        # For wider scans, we'll handle multiple queries in perform_scan
        queries['shodan'] = 'wider_scan_placeholder'
        queries['censys'] = 'wider_scan_placeholder'
        return queries
    
    # Build base query based on input type
    if input_type == 'Domain':
        queries['shodan'] = f'hostname:{target}'
        queries['censys'] = f'hostname: {target}'
    elif input_type == 'Subdomain':
        queries['shodan'] = f'hostname:{target}'
        queries['censys'] = f'hostname: {target}'
    elif input_type == 'IP Address':
        queries['shodan'] = f'ip:{target}'
        queries['censys'] = f'ip: {target}'
    elif input_type == 'IP Range/CIDR':
        queries['shodan'] = f'net:{target}'
        queries['censys'] = f'ip: {target}'
    elif input_type == 'Port-specific scan':
        queries['shodan'] = f'port:{target}'
        queries['censys'] = f'services.port: {target}'
    elif input_type == 'Organization name':
        queries['shodan'] = f'org:"{target}"'
        queries['censys'] = f'autonomous_system.organization: "{target}"'
    elif input_type == 'ASN (Autonomous System Number)':
        queries['shodan'] = f'asn:{target}'
        queries['censys'] = f'autonomous_system.asn: {target}'
    
    # Add service-specific filters using enhanced queries if available
    if shodan_scanner and service_type != 'All services':
        if service_type == 'Databases only':
            # Use detailed database queries for better detection
            db_queries = []
            for query_name, query in shodan_scanner.database_queries.items():
                if 'unauth' in query_name:  # Focus on unauthenticated services
                    db_queries.append(f'({query})')
            if db_queries:
                queries['shodan'] += f' AND ({" OR ".join(db_queries)})'
            else:
                # Fallback to port-based filtering
                db_ports = [str(service['port']) for service in SCAN_CONFIG['services']['databases'].values()]
                port_filter = ' OR '.join([f'port:{port}' for port in db_ports])
                queries['shodan'] += f' AND ({port_filter})'
                queries['censys'] += f' AND ({" OR ".join([f"services.port: {port}" for port in db_ports])})'
        elif service_type == 'File servers only':
            # Use detailed fileserver queries
            fs_queries = []
            for query_name, query in shodan_scanner.fileserver_queries.items():
                if 'anonymous' in query_name or 'open' in query_name:  # Focus on open access
                    fs_queries.append(f'({query})')
            if fs_queries:
                queries['shodan'] += f' AND ({" OR ".join(fs_queries)})'
            else:
                # Fallback to port-based filtering
                fs_ports = [str(service['port']) for service in SCAN_CONFIG['services']['file_servers'].values()]
                port_filter = ' OR '.join([f'port:{port}' for port in fs_ports])
                queries['shodan'] += f' AND ({port_filter})'
                queries['censys'] += f' AND ({" OR ".join([f"services.port: {port}" for port in fs_ports])})'
    else:
        # Use original port-based filtering for backward compatibility
        if service_type == 'Databases only':
            db_ports = [str(service['port']) for service in SCAN_CONFIG['services']['databases'].values()]
            port_filter = ' OR '.join([f'port:{port}' for port in db_ports])
            queries['shodan'] += f' AND ({port_filter})'
            queries['censys'] += f' AND ({" OR ".join([f"services.port: {port}" for port in db_ports])})'
        elif service_type == 'File servers only':
            fs_ports = [str(service['port']) for service in SCAN_CONFIG['services']['file_servers'].values()]
            port_filter = ' OR '.join([f'port:{port}' for port in fs_ports])
            queries['shodan'] += f' AND ({port_filter})'
            queries['censys'] += f' AND ({" OR ".join([f"services.port: {port}" for port in fs_ports])})'
    
    return queries


def search_shodan(shodan_scanner: ShodanScanner, query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Search Shodan API with the given query using enhanced scanner.
    
    Args:
        shodan_scanner: ShodanScanner instance with security analysis
        query: Search query string
        limit: Maximum number of results
        
    Returns:
        List of enhanced search results with security analysis
    """
    if not shodan_scanner:
        return []
    
    try:
        results = shodan_scanner.search(query, limit)
        return results
    except Exception as e:
        print(f"❌ Shodan search error: {e}")
        return []


def search_censys(censys_h, query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Search Censys API with the given query.
    
    Args:
        censys_h: Censys API client
        query: Search query string
        limit: Maximum number of results
        
    Returns:
        List of search results
    """
    if not censys_h:
        return []
    
    try:
        results = censys_h.search(query, per_page=min(limit, 100))
        return list(results)
    except Exception as e:
        print(f"❌ Censys search error: {e}")
        return []


def perform_wider_scan(shodan_scanner: ShodanScanner, censys_h, config: Dict[str, Any], 
                       cache_manager: CacheManager, data_filter: DataFilter, 
                       output_formatter: OutputFormatter) -> List[Dict[str, Any]]:
    """
    Perform wider scan operation with multiple queries for country + product combinations.
    
    Args:
        shodan_scanner: ShodanScanner instance with security analysis
        censys_h: Censys API client
        config: User configuration
        cache_manager: Cache manager instance
        data_filter: Data filter instance
        output_formatter: Output formatter instance
        
    Returns:
        List of filtered scan results with security analysis
    """
    from utils.input_menu import InputMenu
    
    # Check cache first
    cache_key = f"wider_scan_{hash(str(config))}"
    cached_results = cache_manager.get(cache_key)
    
    if cached_results and config.get('use_cache', True):
        print("📋 Using cached results")
        return cached_results
    
    print("🔍 Performing wider scan with multiple queries...")
    
    # Get wider scan queries
    input_menu = InputMenu()
    queries = input_menu.build_wider_scan_queries(config)
    
    if not queries:
        print("❌ No valid queries generated for wider scan")
        return []
    
    print(f"📊 Generated {len(queries)} queries for wider scan")
    
    all_results = []
    wider_config = config.get('wider_scan_config', {})
    limit_per_product = wider_config.get('limit_per_product', 50)
    
    # Execute each query
    for i, query in enumerate(queries, 1):
        print(f"\n🔍 Query {i}/{len(queries)}: {query}")
        
        if shodan_scanner:
            try:
                results = search_shodan(shodan_scanner, query, limit_per_product)
                all_results.extend(results)
                print(f"✅ Found {len(results)} results for query {i}")
            except Exception as e:
                print(f"❌ Error executing query {i}: {e}")
                continue
    
    print(f"\n📊 Total results collected: {len(all_results)}")
    
    # Apply data filtering
    filtered_results = data_filter.filter_results(all_results, config)
    
    # Cache results if enabled
    if config.get('use_cache', True):
        cache_manager.set(cache_key, filtered_results, 
                         ttl=config.get('cache_ttl', 86400))
        print("💾 Results cached for future use")
    
    return filtered_results


def perform_scan(shodan_scanner: ShodanScanner, censys_h, config: Dict[str, Any],  
                 cache_manager: CacheManager, data_filter: DataFilter, 
                 output_formatter: OutputFormatter) -> List[Dict[str, Any]]:
    """
    Perform the main scanning operation with enhanced security analysis.
    
    Args:
        shodan_scanner: ShodanScanner instance with security analysis
        censys_h: Censys API client
        config: User configuration
        cache_manager: Cache manager instance
        data_filter: Data filter instance
        output_formatter: Output formatter instance
        
    Returns:
        List of filtered scan results with security analysis
    """
    # Build queries from configuration with enhanced query selection
    queries = build_query_from_config(config, shodan_scanner)
    
    # Handle wider scan case specially
    if config.get('input_type') == 'Wider Scan (by country + product)':
        return perform_wider_scan(shodan_scanner, censys_h, config, 
                                 cache_manager, data_filter, output_formatter)
    
    # Check cache first
    cache_key = f"scan_{hash(str(config))}"
    cached_results = cache_manager.get(cache_key)
    
    if cached_results and config.get('use_cache', True):
        print("📋 Using cached results")
        return cached_results
    
    print("🔍 Performing fresh scan with security analysis...")
    
    all_results = []
    
    # Search Shodan with enhanced security analysis
    if shodan_scanner and queries['shodan']:
        print(f"🔍 Searching Shodan: {queries['shodan']}")
        shodan_results = search_shodan(shodan_scanner, queries['shodan'], 
                                       config.get('max_results_per_query', 100))
        all_results.extend(shodan_results)
        print(f"✅ Found {len(shodan_results)} Shodan results with security analysis")
    
    # Search Censys (basic results, no security analysis yet)
    if censys_h and queries['censys']:
        print(f"🔍 Searching Censys: {queries['censys']}")
        censys_results = search_censys(censys_h, queries['censys'], 
                                     config.get('max_results_per_query', 100))
        all_results.extend(censys_results)
        print(f"✅ Found {len(censys_results)} Censys results")
    
    # Apply data filtering
    filtered_results = data_filter.filter_results(all_results, config)
    
    # Cache results if enabled
    if config.get('use_cache', True):
        cache_manager.set(cache_key, filtered_results, 
                         ttl=config.get('cache_ttl', 86400))
        print("💾 Results cached for future use")
    
    return filtered_results


def main():
    """Main application entry point."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         Enhanced Misconfiguration Scanner v2.0                ║
    ║         Smart Filtering • Caching • Multiple Outputs          ║
    ║         Advanced Security Analysis • Vulnerability Detection  ║
    ╚═══════════════════════════════════════════════════════════════╝

    [!] DISCLAIMER: Use only on systems you own or have permission to test
    """)
    
    # Initialize API clients
    shodan_api, censys_h = initialise_scanners()
    
    if not shodan_api and not censys_h:
        print("\n❌ No APIs available. Exiting.")
        sys.exit(1)
    
    # Initialize ShodanScanner with enhanced security analysis
    shodan_scanner = None
    if shodan_api:
        shodan_scanner = ShodanScanner(SHODAN_API_KEY)
        print("🔒 Enhanced security analysis enabled")
    
    # Initialize utility components
    cache_manager = CacheManager()
    data_filter = DataFilter()
    output_formatter = OutputFormatter()
    input_menu = InputMenu()
    
    try:
        # Get scan configuration from user
        config = input_menu.get_scan_configuration()
        
        # Perform the scan with enhanced security analysis
        results = perform_scan(shodan_scanner, censys_h, config, 
                             cache_manager, data_filter, output_formatter)
        
        # Display results
        output_formatter.display_results(results, config)
        
        # Show enhanced summary statistics
        if results:
            print(f"\n📊 Enhanced Scan Summary:")
            print(f"   Total results: {len(results)}")
            
            # Count by risk level
            risk_counts = {}
            vulnerability_count = 0
            no_auth_count = 0
            
            for result in results:
                risk = result.get('risk_level', 'unknown')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                
                if result.get('vulnerabilities'):
                    vulnerability_count += 1
                if result.get('authentication_status') == 'none':
                    no_auth_count += 1
            
            for risk, count in risk_counts.items():
                print(f"   {risk.title()} risk: {count}")
            
            print(f"   Vulnerable services: {vulnerability_count}")
            print(f"   No authentication: {no_auth_count}")
        
        print("\n✅ Enhanced scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()