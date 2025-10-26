"""Output formatting utilities for scan results."""

import json
import csv
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from tabulate import tabulate
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class OutputFormatter:
    """Format scan results for various output types."""
    
    def __init__(self):
        """Initialize the output formatter."""
        self.console = Console() if RICH_AVAILABLE else None
    
    def format_json(self, results: List[Dict[str, Any]], 
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format results as JSON string.
        
        Args:
            results: List of scan results
            metadata: Optional metadata to include
            
        Returns:
            JSON formatted string
        """
        output = {
            'scan_metadata': metadata or {},
            'scan_timestamp': datetime.now().isoformat(),
            'total_results': len(results),
            'results': results
        }
        
        return json.dumps(output, indent=2, ensure_ascii=False)
    
    def format_table(self, results: List[Dict[str, Any]], 
                    table_format: str = 'grid') -> str:
        """Format results as a table.
        
        Args:
            results: List of scan results
            table_format: Table format ('grid', 'simple', 'fancy_grid', etc.)
            
        Returns:
            Table formatted string
        """
        if not results:
            return "No results to display."
        
        # Define table headers
        headers = [
            'IP', 'Port', 'Service', 'Product', 'Version', 
            'Country', 'Org', 'Risk Level', 'Auth Status'
        ]
        
        # Prepare table data
        table_data = []
        for result in results:
            row = [
                result.get('ip', 'N/A'),
                result.get('port', 'N/A'),
                result.get('service', 'N/A'),
                result.get('product', 'N/A'),
                result.get('version', 'N/A'),
                result.get('country', 'N/A'),
                result.get('org', 'N/A')[:30] + '...' if len(result.get('org', '')) > 30 else result.get('org', 'N/A'),
                result.get('risk_level', 'N/A'),
                result.get('authentication_status', 'N/A')
            ]
            table_data.append(row)
        
        return tabulate(table_data, headers=headers, tablefmt=table_format)
    
    def format_csv(self, results: List[Dict[str, Any]]) -> str:
        """Format results as CSV string.
        
        Args:
            results: List of scan results
            
        Returns:
            CSV formatted string
        """
        if not results:
            return ""
        
        # Get all possible field names
        fieldnames = set()
        for result in results:
            fieldnames.update(result.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        # Create CSV string
        output = []
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            # Ensure all fields are present
            row = {field: result.get(field, '') for field in fieldnames}
            writer.writerow(row)
        
        return '\n'.join(output)
    
    def format_console(self, results: List[Dict[str, Any]], 
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format results for console display with colors and styling.
        
        Args:
            results: List of scan results
            metadata: Optional metadata to include
            
        Returns:
            Formatted console output string
        """
        if RICH_AVAILABLE:
            return self._format_rich_console(results, metadata)
        else:
            return self._format_simple_console(results, metadata)
    
    def _format_rich_console(self, results: List[Dict[str, Any]], 
                           metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format results using Rich library for enhanced console output."""
        output = []
        
        # Create summary panel
        if metadata:
            summary_text = f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            summary_text += f"Total results: {len(results)}\n"
            if 'target' in metadata:
                summary_text += f"Target: {metadata['target']}\n"
            
            summary_panel = Panel(
                Text(summary_text, style="bold blue"),
                title="Scan Summary",
                border_style="blue"
            )
            output.append(str(summary_panel))
        
        if not results:
            no_results_panel = Panel(
                Text("No results found", style="yellow"),
                title="Results",
                border_style="yellow"
            )
            output.append(str(no_results_panel))
            return '\n\n'.join(output)
        
        # Create results table
        table = Table(title="Scan Results", box=box.ROUNDED)
        
        # Add columns
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Port", style="magenta")
        table.add_column("Service", style="green")
        table.add_column("Product", style="blue")
        table.add_column("Risk", style="red")
        table.add_column("Auth", style="yellow")
        table.add_column("Country", style="white")
        
        # Add rows
        for result in results:
            risk_level = result.get('risk_level', 'unknown')
            risk_style = self._get_risk_style(risk_level)
            
            auth_status = result.get('authentication_status', 'unknown')
            auth_style = self._get_auth_style(auth_status)
            
            table.add_row(
                result.get('ip', 'N/A'),
                str(result.get('port', 'N/A')),
                result.get('service', 'N/A'),
                result.get('product', 'N/A'),
                Text(risk_level.upper(), style=risk_style),
                Text(auth_status, style=auth_style),
                result.get('country', 'N/A')
            )
        
        output.append(str(table))
        
        # Add detailed information for high-risk results
        high_risk_results = [r for r in results if r.get('risk_level', '').lower() in ['high', 'critical']]
        if high_risk_results:
            high_risk_panel = Panel(
                Text(f"Found {len(high_risk_results)} high-risk misconfigurations that require immediate attention!", 
                     style="bold red"),
                title="⚠️  High Risk Alert",
                border_style="red"
            )
            output.append(str(high_risk_panel))
        
        return '\n\n'.join(output)
    
    def _format_simple_console(self, results: List[Dict[str, Any]], 
                             metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format results for simple console output without Rich."""
        output = []
        
        # Header
        output.append("=" * 80)
        output.append("MISCONFIGURATION SCAN RESULTS")
        output.append("=" * 80)
        
        if metadata:
            output.append(f"Target: {metadata.get('target', 'N/A')}")
            output.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Total Results: {len(results)}")
            output.append("")
        
        if not results:
            output.append("No results found.")
            return '\n'.join(output)
        
        # Results table
        output.append(f"{'IP':<15} {'Port':<6} {'Service':<12} {'Product':<15} {'Risk':<8} {'Auth':<10} {'Country':<15}")
        output.append("-" * 80)
        
        for result in results:
            ip = result.get('ip', 'N/A')
            port = str(result.get('port', 'N/A'))
            service = result.get('service', 'N/A')
            product = result.get('product', 'N/A')
            risk = result.get('risk_level', 'N/A')
            auth = result.get('authentication_status', 'N/A')
            country = result.get('country', 'N/A')
            
            output.append(f"{ip:<15} {port:<6} {service:<12} {product:<15} {risk:<8} {auth:<10} {country:<15}")
        
        # Summary
        high_risk_count = len([r for r in results if r.get('risk_level', '').lower() in ['high', 'critical']])
        no_auth_count = len([r for r in results if r.get('authentication_status', '') == 'none'])
        
        output.append("")
        output.append("SUMMARY:")
        output.append(f"  High Risk: {high_risk_count}")
        output.append(f"  No Authentication: {no_auth_count}")
        
        if high_risk_count > 0:
            output.append("")
            output.append("⚠️  WARNING: High-risk misconfigurations detected!")
        
        return '\n'.join(output)
    
    def _get_risk_style(self, risk_level: str) -> str:
        """Get Rich style for risk level."""
        risk_styles = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        return risk_styles.get(risk_level.lower(), 'white')
    
    def _get_auth_style(self, auth_status: str) -> str:
        """Get Rich style for authentication status."""
        auth_styles = {
            'none': 'bold red',
            'optional': 'yellow',
            'required': 'green',
            'error': 'red'
        }
        return auth_styles.get(auth_status.lower(), 'white')
    
    def export_to_file(self, results: List[Dict[str, Any]], 
                      filename: str, format_type: str = 'json',
                      metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Export results to a file.
        
        Args:
            results: List of scan results
            filename: Output filename
            format_type: Output format ('json', 'csv', 'table')
            metadata: Optional metadata to include
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
            
            if format_type.lower() == 'json':
                content = self.format_json(results, metadata)
            elif format_type.lower() == 'csv':
                content = self.format_csv(results)
            elif format_type.lower() == 'table':
                content = self.format_table(results)
            else:
                raise ValueError(f"Unsupported format type: {format_type}")
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            print(f"Error exporting to file {filename}: {e}")
            return False
    
    def display_results(self, results: List[Dict[str, Any]], 
                       format_type: str = 'console',
                       metadata: Optional[Dict[str, Any]] = None):
        """Display results in the specified format.
        
        Args:
            results: List of scan results
            format_type: Display format ('console', 'table', 'json')
            metadata: Optional metadata to include
        """
        if format_type.lower() == 'console':
            output = self.format_console(results, metadata)
        elif format_type.lower() == 'table':
            output = self.format_table(results)
        elif format_type.lower() == 'json':
            output = self.format_json(results, metadata)
        else:
            output = f"Unsupported format type: {format_type}"
        
        print(output)
    
    def get_summary_table(self, results: List[Dict[str, Any]]) -> str:
        """Generate a summary table of results.
        
        Args:
            results: List of scan results
            
        Returns:
            Summary table as string
        """
        if not results:
            return "No results to summarize."
        
        # Calculate statistics
        stats = {
            'total': len(results),
            'by_service': {},
            'by_risk': {},
            'by_country': {},
            'high_risk': 0,
            'no_auth': 0
        }
        
        for result in results:
            # Service counts
            service = result.get('service', 'unknown')
            stats['by_service'][service] = stats['by_service'].get(service, 0) + 1
            
            # Risk counts
            risk = result.get('risk_level', 'unknown')
            stats['by_risk'][risk] = stats['by_risk'].get(risk, 0) + 1
            
            # Country counts
            country = result.get('country', 'unknown')
            stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
            
            # Special counts
            if risk.lower() in ['high', 'critical']:
                stats['high_risk'] += 1
            
            if result.get('authentication_status', '').lower() == 'none':
                stats['no_auth'] += 1
        
        # Create summary table
        summary_data = [
            ['Total Results', str(stats['total'])],
            ['High Risk', str(stats['high_risk'])],
            ['No Authentication', str(stats['no_auth'])],
            ['', ''],
            ['Top Services', ''],
        ]
        
        # Add top services
        top_services = sorted(stats['by_service'].items(), key=lambda x: x[1], reverse=True)[:5]
        for service, count in top_services:
            summary_data.append([f'  {service}', str(count)])
        
        summary_data.extend([
            ['', ''],
            ['Top Countries', ''],
        ])
        
        # Add top countries
        top_countries = sorted(stats['by_country'].items(), key=lambda x: x[1], reverse=True)[:5]
        for country, count in top_countries:
            summary_data.append([f'  {country}', str(count)])
        
        return tabulate(summary_data, headers=['Metric', 'Count'], tablefmt='grid')
