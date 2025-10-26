"""Interactive input menu using inquirer for scan configuration."""

import inquirer
from typing import Dict, Any, List, Optional
import re
import ipaddress


class InputMenu:
    """Interactive menu system for scan configuration using inquirer."""
    
    def __init__(self):
        """Initialize the input menu."""
        self.input_types = [
            'Domain',
            'Subdomain', 
            'IP Address',
            'IP Range/CIDR',
            'Port-specific scan',
            'Organization name',
            'ASN (Autonomous System Number)',
            'Wider Scan (by country + product)'
        ]
        
        self.service_types = [
            'All services',
            'Databases only',
            'File servers only',
            'Custom selection'
        ]
        
        self.output_formats = [
            'Console (pretty)',
            'Table',
            'JSON',
            'CSV'
        ]
        
        self.risk_levels = [
            'All',
            'High and Critical only',
            'Medium and above',
            'Low and above'
        ]
    
    def get_scan_configuration(self) -> Dict[str, Any]:
        """Get complete scan configuration from user.
        
        Returns:
            Dictionary with scan configuration
        """
        print("\n" + "="*60)
        print("MISCONFIGURATION SCANNER CONFIGURATION")
        print("="*60)
        
        config = {}
        
        # Input type selection
        config.update(self._get_input_type())
        
        # Service type selection
        config.update(self._get_service_type())
        
        # Output format selection
        config.update(self._get_output_format())
        
        # Filter options
        config.update(self._get_filter_options())
        
        # Scan limits
        config.update(self._get_scan_limits())
        
        # Cache options
        config.update(self._get_cache_options())
        
        return config
    
    def _get_input_type(self) -> Dict[str, Any]:
        """Get input type and target from user."""
        questions = [
            inquirer.List('input_type',
                         message="Select input type:",
                         choices=self.input_types,
                         default='Domain')
        ]
        
        answers = inquirer.prompt(questions)
        input_type = answers['input_type']
        
        # Handle wider scan specially
        if input_type == 'Wider Scan (by country + product)':
            wider_config = self._get_wider_scan_config()
            return {
                'input_type': input_type,
                'target': 'wider_scan',
                'wider_scan_config': wider_config
            }
        
        # Get target based on input type
        target_question = self._get_target_question(input_type)
        target_answers = inquirer.prompt([target_question])
        
        return {
            'input_type': input_type,
            'target': target_answers['target']
        }
    
    def _get_target_question(self, input_type: str):
        """Get appropriate target question based on input type."""
        if input_type == 'Domain':
            return inquirer.Text('target',
                               message="Enter domain (e.g., example.com):",
                               validate=lambda _, x: self._validate_domain(x))
        
        elif input_type == 'Subdomain':
            return inquirer.Text('target',
                               message="Enter subdomain (e.g., api.example.com):",
                               validate=lambda _, x: self._validate_domain(x))
        
        elif input_type == 'IP Address':
            return inquirer.Text('target',
                               message="Enter IP address (e.g., 192.168.1.1):",
                               validate=lambda _, x: self._validate_ip(x))
        
        elif input_type == 'IP Range/CIDR':
            return inquirer.Text('target',
                               message="Enter IP range/CIDR (e.g., 192.168.1.0/24):",
                               validate=lambda _, x: self._validate_cidr(x))
        
        elif input_type == 'Port-specific scan':
            return inquirer.Text('target',
                               message="Enter port (e.g., 27017) or port:27017:",
                               validate=lambda _, x: self._validate_port(x))
        
        elif input_type == 'Organization name':
            return inquirer.Text('target',
                               message="Enter organization name (e.g., Acme Corp):")
        
        elif input_type == 'ASN (Autonomous System Number)':
            return inquirer.Text('target',
                               message="Enter ASN (e.g., AS12345):",
                               validate=lambda _, x: self._validate_asn(x))
        
        else:
            return inquirer.Text('target',
                               message="Enter target:")
    
    def _get_service_type(self) -> Dict[str, Any]:
        """Get service type selection from user."""
        questions = [
            inquirer.List('service_type',
                         message="Select services to scan:",
                         choices=self.service_types,
                         default='All services')
        ]
        
        answers = inquirer.prompt(questions)
        service_type = answers['service_type']
        
        # If custom selection, get specific services
        if service_type == 'Custom selection':
            custom_services = self._get_custom_services()
            return {
                'service_type': 'custom',
                'custom_services': custom_services
            }
        
        return {
            'service_type': service_type.lower().replace(' ', '_')
        }
    
    def _get_custom_services(self) -> List[str]:
        """Get custom service selection from user."""
        available_services = [
            'mongodb', 'redis', 'elasticsearch', 'mysql', 'postgresql',
            'mssql', 'cassandra', 'ftp', 'smb', 'nfs', 'rsync'
        ]
        
        questions = [
            inquirer.Checkbox('services',
                            message="Select specific services:",
                            choices=available_services,
                            default=['mongodb', 'redis'])
        ]
        
        answers = inquirer.prompt(questions)
        return answers['services']
    
    def _get_output_format(self) -> Dict[str, Any]:
        """Get output format selection from user."""
        questions = [
            inquirer.List('output_format',
                         message="Select output format:",
                         choices=self.output_formats,
                         default='Console (pretty)')
        ]
        
        answers = inquirer.prompt(questions)
        format_name = answers['output_format']
        
        # Convert to format type
        format_mapping = {
            'Console (pretty)': 'console',
            'Table': 'table',
            'JSON': 'json',
            'CSV': 'csv'
        }
        
        return {
            'output_format': format_mapping[format_name]
        }
    
    def _get_filter_options(self) -> Dict[str, Any]:
        """Get filter options from user."""
        questions = [
            inquirer.List('risk_filter',
                         message="Filter by risk level:",
                         choices=self.risk_levels,
                         default='All'),
            
            inquirer.Text('country_filter',
                         message="Filter by country code (optional, e.g., US, UK):",
                         default=""),
            
            inquirer.Text('org_filter',
                         message="Filter by organization (optional):",
                         default="")
        ]
        
        answers = inquirer.prompt(questions)
        
        filters = {}
        
        # Process risk filter
        risk_mapping = {
            'All': None,
            'High and Critical only': 'high',
            'Medium and above': 'medium',
            'Low and above': 'low'
        }
        filters['min_risk'] = risk_mapping[answers['risk_filter']]
        
        # Process country filter
        if answers['country_filter'].strip():
            filters['countries'] = [c.strip().upper() for c in answers['country_filter'].split(',')]
        
        # Process organization filter
        if answers['org_filter'].strip():
            filters['organizations'] = [o.strip() for o in answers['org_filter'].split(',')]
        
        return {'filters': filters}
    
    def _get_scan_limits(self) -> Dict[str, Any]:
        """Get scan limits from user."""
        questions = [
            inquirer.Text('max_results',
                        message="Maximum results per query (default 50):",
                        default="50",
                        validate=lambda _, x: self._validate_number(x)),
            
            inquirer.Text('global_limit',
                         message="Global maximum results (default 200):",
                         default="200",
                         validate=lambda _, x: self._validate_number(x))
        ]
        
        answers = inquirer.prompt(questions)
        
        return {
            'max_results': int(answers['max_results']),
            'global_limit': int(answers['global_limit'])
        }
    
    def _get_wider_scan_config(self) -> Dict[str, Any]:
        """Get wider scan configuration from user.
        
        Returns:
            Dictionary with wider scan configuration
        """
        print("\n" + "="*60)
        print("WIDER SCAN CONFIGURATION")
        print("="*60)
        
        # Country selection
        questions = [
            inquirer.Text('countries',
                         message="Enter country codes (comma-separated, e.g., US,UK,DE):",
                         validate=lambda _, x: self._validate_countries(x))
        ]
        
        answers = inquirer.prompt(questions)
        countries = [c.strip().upper() for c in answers['countries'].split(',')]
        
        # Product selection
        available_products = {
            'databases': ['mongodb', 'redis', 'elasticsearch', 'mysql', 'postgresql', 'mssql', 'cassandra', 'memcached', 'couchdb'],
            'file_servers': ['ftp', 'smb', 'nfs', 'rsync', 'webdav', 'tftp']
        }
        
        all_products = available_products['databases'] + available_products['file_servers']
        
        questions = [
            inquirer.Checkbox('products',
                            message="Select products to scan:",
                            choices=all_products,
                            default=['mongodb', 'redis'])
        ]
        
        answers = inquirer.prompt(questions)
        selected_products = answers['products']
        
        # Authentication filter
        questions = [
            inquirer.Confirm('auth_filter',
                           message="Only show unauthenticated services?",
                           default=True)
        ]
        
        answers = inquirer.prompt(questions)
        auth_filter = answers['auth_filter']
        
        # Result limit per product
        questions = [
            inquirer.Text('limit_per_product',
                         message="Maximum results per product (default 50):",
                         default="50",
                         validate=lambda _, x: self._validate_number(x))
        ]
        
        answers = inquirer.prompt(questions)
        limit_per_product = int(answers['limit_per_product'])
        
        return {
            'countries': countries,
            'products': selected_products,
            'auth_filter': auth_filter,
            'limit_per_product': limit_per_product
        }
    
    def _get_cache_options(self) -> Dict[str, Any]:
        questions = [
            inquirer.Confirm('use_cache',
                           message="Enable caching?",
                           default=True),
            
            inquirer.Text('cache_ttl',
                         message="Cache TTL in hours (default 24):",
                         default="24",
                         validate=lambda _, x: self._validate_number(x))
        ]
        
        answers = inquirer.prompt(questions)
        
        return {
            'use_cache': answers['use_cache'],
            'cache_ttl': int(answers['cache_ttl'])
        }
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if not domain:
            return False
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain))
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_cidr(self, cidr: str) -> bool:
        """Validate CIDR format."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def _validate_port(self, port: str) -> bool:
        """Validate port format."""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def _validate_asn(self, asn: str) -> bool:
        """Validate ASN format."""
        asn_pattern = r'^AS\d+$'
        return bool(re.match(asn_pattern, asn.upper()))
    
    def _validate_countries(self, countries: str) -> bool:
        """Validate country codes format."""
        if not countries:
            return False
        
        # Basic validation - check for 2-letter country codes
        country_codes = [c.strip().upper() for c in countries.split(',')]
        for code in country_codes:
            if len(code) != 2 or not code.isalpha():
                return False
        
        return True
    
    def build_query(self, config: Dict[str, Any]) -> str:
        """Build Shodan query from configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Shodan query string
        """
        input_type = config['input_type']
        target = config['target']
        
        # Handle wider scan case
        if input_type == 'Wider Scan (by country + product)':
            queries = self.build_wider_scan_queries(config)
            return queries[0] if queries else ''
        
        if input_type == 'Domain':
            return f'hostname:{target}'
        
        elif input_type == 'Subdomain':
            return f'hostname:{target}'
        
        elif input_type == 'IP Address':
            return f'ip:{target}'
        
        elif input_type == 'IP Range/CIDR':
            return f'net:{target}'
        
        elif input_type == 'Port-specific scan':
            if target.startswith('port:'):
                return target
            else:
                return f'port:{target}'
        
        elif input_type == 'Organization name':
            return f'org:"{target}"'
        
        elif input_type == 'ASN (Autonomous System Number)':
            return f'asn:{target}'
        
        else:
            return target
    
    def build_wider_scan_queries(self, config: Dict[str, Any]) -> List[str]:
        """Build multiple Shodan queries for wider scan configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of Shodan query strings
        """
        wider_config = config.get('wider_scan_config', {})
        countries = wider_config.get('countries', [])
        products = wider_config.get('products', [])
        auth_filter = wider_config.get('auth_filter', True)
        
        # Product to port mapping
        product_ports = {
            'mongodb': '27017',
            'redis': '6379',
            'elasticsearch': '9200',
            'mysql': '3306',
            'postgresql': '5432',
            'mssql': '1433',
            'cassandra': '9042',
            'memcached': '11211',
            'couchdb': '5984',
            'ftp': '21',
            'smb': '445',
            'nfs': '2049',
            'rsync': '873',
            'webdav': '80',
            'tftp': '69'
        }
        
        # Product to Shodan product name mapping
        product_names = {
            'mongodb': 'MongoDB',
            'redis': 'Redis',
            'elasticsearch': 'Elasticsearch',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'mssql': 'Microsoft SQL Server',
            'cassandra': 'Cassandra',
            'memcached': 'memcached',
            'couchdb': 'CouchDB',
            'ftp': 'FTP',
            'smb': 'Samba',
            'nfs': 'NFS',
            'rsync': 'rsync',
            'webdav': 'WebDAV',
            'tftp': 'TFTP'
        }
        
        queries = []
        
        # Build queries for each country and product combination
        for country in countries:
            for product in products:
                if product in product_ports and product in product_names:
                    query_parts = [
                        f'country:{country}',
                        f'port:{product_ports[product]}',
                        f'product:{product_names[product]}'
                    ]
                    
                    if auth_filter:
                        query_parts.append('-authentication')
                    
                    queries.append(' '.join(query_parts))
        
        return queries
    
    def _validate_number(self, number: str) -> bool:
        try:
            num = int(number)
            return num > 0
        except ValueError:
            return False
    
    def confirm_scan(self, config: Dict[str, Any], query: str) -> bool:
        """Ask user to confirm scan configuration.
        
        Args:
            config: Scan configuration
            query: Generated query string
            
        Returns:
            True if user confirms, False otherwise
        """
        print("\n" + "="*60)
        print("SCAN CONFIGURATION SUMMARY")
        print("="*60)
        
        print(f"Input Type: {config['input_type']}")
        print(f"Target: {config['target']}")
        print(f"Query: {query}")
        print(f"Service Type: {config['service_type']}")
        print(f"Output Format: {config['output_format']}")
        print(f"Max Results per Query: {config['max_results']}")
        print(f"Global Limit: {config['global_limit']}")
        print(f"Use Cache: {config['use_cache']}")
        
        if config.get('filters'):
            filters = config['filters']
            if filters.get('min_risk'):
                print(f"Risk Filter: {filters['min_risk']} and above")
            if filters.get('countries'):
                print(f"Country Filter: {', '.join(filters['countries'])}")
            if filters.get('organizations'):
                print(f"Organization Filter: {', '.join(filters['organizations'])}")
        
        questions = [
            inquirer.Confirm('confirm',
                           message="Proceed with scan?",
                           default=True)
        ]
        
        answers = inquirer.prompt(questions)
        return answers['confirm']
