import logging
from typing import Dict, List, Optional
from datetime import datetime

class Reporter:
    def __init__(self):
        self.logger = logging.getLogger('Reporter')
        
    def generate_report(self, 
                       target_url: str,
                       pages_crawled: int,
                       vulnerabilities_found: List[Dict],
                       scan_type: str = "fast",
                       elapsed_time: float = 0.0) -> Dict:
        """Generate a comprehensive scan report"""
        try:
            # Calculate statistics
            total_vulnerabilities = len(vulnerabilities_found)
            severity_counts = {
                'critical': sum(1 for v in vulnerabilities_found if v.get('severity') == 'critical'),
                'high': sum(1 for v in vulnerabilities_found if v.get('severity') == 'high'),
                'medium': sum(1 for v in vulnerabilities_found if v.get('severity') == 'medium'),
                'low': sum(1 for v in vulnerabilities_found if v.get('severity') == 'low')
            }
            
            # Generate recommendations based on findings
            recommendations = self._generate_recommendations(vulnerabilities_found)
            
            # Create the report
            report = {
                'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'target_url': target_url,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time': round(elapsed_time, 2),
                'stats': {
                    'pages_crawled': pages_crawled,
                    'total_vulnerabilities': total_vulnerabilities,
                    'severity_counts': severity_counts
                },
                'vulnerabilities': vulnerabilities_found,
                'recommendations': recommendations
            }
            
            self.logger.info(f"Generated report for {target_url}")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
            
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations based on found vulnerabilities"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
            
        # Generate type-specific recommendations
        for vuln_type, vulns in vuln_types.items():
            if vuln_type == 'xss':
                recommendations.append(
                    f"Implement Content Security Policy (CSP) headers to prevent XSS attacks. "
                    f"Found {len(vulns)} XSS vulnerabilities."
                )
            elif vuln_type == 'sqli':
                recommendations.append(
                    f"Use parameterized queries or prepared statements for all database operations. "
                    f"Found {len(vulns)} SQL injection vulnerabilities."
                )
            elif vuln_type == 'csrf':
                recommendations.append(
                    f"Implement CSRF tokens for all forms and state-changing requests. "
                    f"Found {len(vulns)} CSRF vulnerabilities."
                )
                
        return recommendations 