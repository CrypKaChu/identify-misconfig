"""Shared ShodanScanner class for misconfiguration detection."""

from typing import Dict, List, Any
from shodan import Shodan


class ShodanScanner:
    """Scanner class to identify misconfigured services using Shodan API"""

    def __init__(self, api_key: str):
        """
        Initialize Shodan scanner with API key

        Args:
            api_key: Your Shodan API key
        """
        self.api = Shodan(api_key)

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

        except Exception as e:
            print(f"❌ Shodan search error: {e}")

        return results
