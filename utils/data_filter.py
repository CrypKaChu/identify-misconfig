"""Data filtering utilities for scan results."""

from typing import List, Dict, Any, Optional
import re
from datetime import datetime


class DataFilter:
    """Filter and clean scan results data."""
    
    def __init__(self):
        """Initialize the data filter."""
        self.unnecessary_fields = {
            'raw_data', 'timestamp', 'data', 'banner', 'extra', 'metadata',
            'internal_notes', 'debug_info', 'temp_data'
        }
        
        self.risk_levels = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
    
    def filter_unnecessary_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove unnecessary fields from scan results.
        
        Args:
            data: Raw scan result data
            
        Returns:
            Cleaned data with unnecessary fields removed
        """
        if isinstance(data, dict):
            filtered = {}
            for key, value in data.items():
                if key not in self.unnecessary_fields:
                    if isinstance(value, dict):
                        filtered[key] = self.filter_unnecessary_fields(value)
                    elif isinstance(value, list):
                        filtered[key] = [self.filter_unnecessary_fields(item) 
                                       if isinstance(item, dict) else item 
                                       for item in value]
                    else:
                        filtered[key] = value
            return filtered
        return data
    
    def filter_by_risk_level(self, results: List[Dict[str, Any]], 
                           min_risk: str = 'low') -> List[Dict[str, Any]]:
        """Filter results by minimum risk level.
        
        Args:
            results: List of scan results
            min_risk: Minimum risk level ('low', 'medium', 'high', 'critical')
            
        Returns:
            Filtered results meeting minimum risk level
        """
        min_risk_score = self.risk_levels.get(min_risk.lower(), 1)
        
        filtered = []
        for result in results:
            risk_level = result.get('risk_level', 'low').lower()
            risk_score = self.risk_levels.get(risk_level, 1)
            
            if risk_score >= min_risk_score:
                filtered.append(result)
        
        return filtered
    
    def filter_by_service_type(self, results: List[Dict[str, Any]], 
                             service_types: List[str]) -> List[Dict[str, Any]]:
        """Filter results by service type.
        
        Args:
            results: List of scan results
            service_types: List of service types to include
            
        Returns:
            Filtered results matching service types
        """
        if not service_types or 'all' in service_types:
            return results
        
        filtered = []
        for result in results:
            service = result.get('service', '').lower()
            if any(st.lower() in service for st in service_types):
                filtered.append(result)
        
        return filtered
    
    def filter_by_country(self, results: List[Dict[str, Any]], 
                        countries: List[str]) -> List[Dict[str, Any]]:
        """Filter results by country.
        
        Args:
            results: List of scan results
            countries: List of country codes/names to include
            
        Returns:
            Filtered results from specified countries
        """
        if not countries:
            return results
        
        filtered = []
        for result in results:
            country = result.get('country', '').lower()
            if any(c.lower() in country for c in countries):
                filtered.append(result)
        
        return filtered
    
    def filter_by_authentication_status(self, results: List[Dict[str, Any]], 
                                     auth_status: str) -> List[Dict[str, Any]]:
        """Filter results by authentication status.
        
        Args:
            results: List of scan results
            auth_status: Authentication status ('none', 'optional', 'required', 'error')
            
        Returns:
            Filtered results matching authentication status
        """
        if not auth_status:
            return results
        
        filtered = []
        for result in results:
            result_auth = result.get('authentication_status', '').lower()
            if result_auth == auth_status.lower():
                filtered.append(result)
        
        return filtered
    
    def filter_by_port(self, results: List[Dict[str, Any]], 
                      ports: List[int]) -> List[Dict[str, Any]]:
        """Filter results by port number.
        
        Args:
            results: List of scan results
            ports: List of port numbers to include
            
        Returns:
            Filtered results matching port numbers
        """
        if not ports:
            return results
        
        filtered = []
        for result in results:
            port = result.get('port', 0)
            if port in ports:
                filtered.append(result)
        
        return filtered
    
    def filter_by_organization(self, results: List[Dict[str, Any]], 
                             organizations: List[str]) -> List[Dict[str, Any]]:
        """Filter results by organization.
        
        Args:
            results: List of scan results
            organizations: List of organization names to include
            
        Returns:
            Filtered results from specified organizations
        """
        if not organizations:
            return results
        
        filtered = []
        for result in results:
            org = result.get('org', '').lower()
            if any(o.lower() in org for o in organizations):
                filtered.append(result)
        
        return filtered
    
    def filter_duplicates(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate results based on IP and port combination.
        
        Args:
            results: List of scan results
            
        Returns:
            Results with duplicates removed
        """
        seen = set()
        filtered = []
        
        for result in results:
            ip = result.get('ip', '')
            port = result.get('port', 0)
            key = f"{ip}:{port}"
            
            if key not in seen:
                seen.add(key)
                filtered.append(result)
        
        return filtered
    
    def apply_filters(self, results: List[Dict[str, Any]], 
                     filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply multiple filters to results.
        
        Args:
            results: List of scan results
            filters: Dictionary of filter criteria
            
        Returns:
            Filtered results
        """
        filtered_results = results.copy()
        
        # Apply each filter if specified
        if 'min_risk' in filters:
            filtered_results = self.filter_by_risk_level(
                filtered_results, filters['min_risk']
            )
        
        if 'service_types' in filters:
            filtered_results = self.filter_by_service_type(
                filtered_results, filters['service_types']
            )
        
        if 'countries' in filters:
            filtered_results = self.filter_by_country(
                filtered_results, filters['countries']
            )
        
        if 'auth_status' in filters:
            filtered_results = self.filter_by_authentication_status(
                filtered_results, filters['auth_status']
            )
        
        if 'ports' in filters:
            filtered_results = self.filter_by_port(
                filtered_results, filters['ports']
            )
        
        if 'organizations' in filters:
            filtered_results = self.filter_by_organization(
                filtered_results, filters['organizations']
            )
        
        # Always remove duplicates and unnecessary fields
        filtered_results = self.filter_duplicates(filtered_results)
        
        # Clean unnecessary fields from each result
        cleaned_results = []
        for result in filtered_results:
            cleaned_result = self.filter_unnecessary_fields(result)
            cleaned_results.append(cleaned_result)
        
        return cleaned_results
    
    def filter_results(self, results: List[Dict[str, Any]], 
                       config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter results based on configuration.
        
        Args:
            results: List of scan results
            config: Full configuration dictionary containing filters
            
        Returns:
            Filtered results
        """
        # Extract filter criteria from config
        filters = config.get('filters', {})
        
        # Apply max results limit if specified
        max_results = config.get('global_limit', config.get('max_results', None))
        if max_results and len(results) > max_results:
            results = results[:max_results]
        
        # Apply filters using existing method
        if filters:
            return self.apply_filters(results, filters)
        
        # If no filters, still clean and deduplicate
        results = self.filter_duplicates(results)
        cleaned_results = []
        for result in results:
            cleaned_result = self.filter_unnecessary_fields(result)
            cleaned_results.append(cleaned_result)
        
        return cleaned_results
    
    def get_summary_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for filtered results.
        
        Args:
            results: List of scan results
            
        Returns:
            Summary statistics dictionary
        """
        stats = {
            'total_results': len(results),
            'by_service': {},
            'by_risk_level': {},
            'by_country': {},
            'by_auth_status': {},
            'high_risk_count': 0,
            'no_auth_count': 0,
            'vulnerable_count': 0
        }
        
        for result in results:
            # Service type counts
            service = result.get('service', 'unknown')
            stats['by_service'][service] = stats['by_service'].get(service, 0) + 1
            
            # Risk level counts
            risk = result.get('risk_level', 'unknown')
            stats['by_risk_level'][risk] = stats['by_risk_level'].get(risk, 0) + 1
            
            # Country counts
            country = result.get('country', 'unknown')
            stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
            
            # Authentication status counts
            auth = result.get('authentication_status', 'unknown')
            stats['by_auth_status'][auth] = stats['by_auth_status'].get(auth, 0) + 1
            
            # Special counts
            if risk in ['high', 'critical']:
                stats['high_risk_count'] += 1
            
            if auth == 'none':
                stats['no_auth_count'] += 1
            
            if result.get('vulnerabilities'):
                stats['vulnerable_count'] += 1
        
        return stats
