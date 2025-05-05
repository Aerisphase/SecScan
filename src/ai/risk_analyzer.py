import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class RiskAnalyzer:
    """
    Analyzes security risks and provides severity ratings for vulnerabilities
    """
    def __init__(self):
        self.risk_db_path = Path("data/risk_profiles.json")
        self.risk_profiles = self._load_risk_profiles()
        self.waf_impact_factors = {
            "Cloudflare": 0.7,
            "AWS WAF": 0.75,
            "Akamai": 0.8,
            "Imperva": 0.65,
            "F5": 0.7,
            "ModSecurity": 0.8,
            "Sucuri": 0.75,
            "Fortinet": 0.7,
            "Barracuda": 0.75,
            "Generic WAF": 0.85
        }
        
    def _load_risk_profiles(self) -> Dict:
        """Load risk profiles from database or create default profiles"""
        if self.risk_db_path.exists():
            try:
                with open(self.risk_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading risk profiles: {e}")
                return self._create_default_profiles()
        else:
            return self._create_default_profiles()
            
    def _create_default_profiles(self) -> Dict:
        """Create default risk profiles"""
        profiles = {
            "vulnerability_types": {
                "XSS": {
                    "base_score": 7.5,
                    "description": "Cross-site scripting vulnerability",
                    "impact_factors": {
                        "authenticated": 0.9,
                        "unauthenticated": 1.0,
                        "stored": 1.2,
                        "reflected": 1.0,
                        "dom": 1.1
                    }
                },
                "SQLi": {
                    "base_score": 8.5,
                    "description": "SQL injection vulnerability",
                    "impact_factors": {
                        "authenticated": 0.9,
                        "unauthenticated": 1.0,
                        "blind": 0.9,
                        "error-based": 1.0,
                        "time-based": 0.95,
                        "union-based": 1.1
                    }
                },
                "CSRF": {
                    "base_score": 6.8,
                    "description": "Cross-site request forgery vulnerability",
                    "impact_factors": {
                        "authenticated": 1.1,
                        "unauthenticated": 0.8,
                        "state-changing": 1.2,
                        "info-disclosure": 0.9
                    }
                },
                "SSRF": {
                    "base_score": 7.5,
                    "description": "Server-side request forgery vulnerability",
                    "impact_factors": {
                        "internal-network": 1.2,
                        "cloud-metadata": 1.3,
                        "external-only": 0.8
                    }
                },
                "RCE": {
                    "base_score": 9.5,
                    "description": "Remote code execution vulnerability",
                    "impact_factors": {
                        "authenticated": 0.9,
                        "unauthenticated": 1.2,
                        "limited-commands": 0.8,
                        "full-shell": 1.2
                    }
                },
                "LFI": {
                    "base_score": 7.0,
                    "description": "Local file inclusion vulnerability",
                    "impact_factors": {
                        "path-traversal": 1.1,
                        "config-access": 1.2,
                        "log-poisoning": 1.3
                    }
                }
            },
            "context_factors": {
                "payment_processing": 1.3,
                "authentication": 1.2,
                "admin_interface": 1.25,
                "user_data": 1.15,
                "public_content": 0.9,
                "internal_api": 1.1,
                "external_api": 1.0
            },
            "waf_bypass_factors": {
                "encoding_variation": 0.9,
                "case_variation": 0.95,
                "html_obfuscation": 0.85,
                "js_obfuscation": 0.8,
                "parameter_pollution": 0.75,
                "custom_headers": 0.85
            }
        }
        
        # Save default profiles
        self.risk_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.risk_db_path, 'w', encoding='utf-8') as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)
            
        return profiles
        
    def calculate_risk_score(self, vuln_type: str, context: Dict, waf_detected: Optional[str] = None) -> Dict:
        """
        Calculate risk score for a vulnerability
        
        Args:
            vuln_type: Type of vulnerability (XSS, SQLi, etc.)
            context: Additional context about the vulnerability
            waf_detected: WAF detected during scanning (if any)
            
        Returns:
            Dict containing risk score and details
        """
        # Get base score for vulnerability type
        vuln_profiles = self.risk_profiles.get("vulnerability_types", {})
        vuln_info = vuln_profiles.get(vuln_type, {"base_score": 5.0, "impact_factors": {}})
        
        base_score = vuln_info.get("base_score", 5.0)
        impact_factors = vuln_info.get("impact_factors", {})
        
        # Apply vulnerability-specific impact factors
        score = base_score
        for factor, value in context.items():
            if factor in impact_factors and value:
                score *= impact_factors[factor]
        
        # Apply context factors
        context_factors = self.risk_profiles.get("context_factors", {})
        for context_type, factor in context_factors.items():
            if context.get(context_type, False):
                score *= factor
                
        # Apply WAF bypass factor if WAF detected
        if waf_detected:
            waf_factor = self.waf_impact_factors.get(waf_detected, 0.85)
            score *= waf_factor
            
            # Apply specific bypass techniques if used
            bypass_factors = self.risk_profiles.get("waf_bypass_factors", {})
            for technique, factor in bypass_factors.items():
                if context.get(f"bypass_{technique}", False):
                    score *= factor
        
        # Normalize score to 0-10 range
        normalized_score = min(10.0, max(0.0, score))
        
        # Determine severity level
        severity = self._determine_severity(normalized_score)
        
        return {
            "score": round(normalized_score, 1),
            "severity": severity,
            "base_score": base_score,
            "waf_detected": waf_detected,
            "timestamp": datetime.now().isoformat()
        }
    
    def _determine_severity(self, score: float) -> str:
        """Determine severity level based on risk score"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 2.0:
            return "Low"
        else:
            return "Info"
            
    def analyze_waf_bypass_potential(self, waf_type: str, vulnerability: Dict) -> Dict:
        """
        Analyze potential for WAF bypass for a specific vulnerability
        
        Args:
            waf_type: Type of WAF detected
            vulnerability: Vulnerability details
            
        Returns:
            Dict containing bypass potential and recommendations
        """
        bypass_techniques = {
            "Cloudflare": [
                "URL encoding variations",
                "Multi-part request body",
                "JSON payload format",
                "Custom headers"
            ],
            "AWS WAF": [
                "Parameter pollution",
                "Nested JSON objects",
                "Unicode encoding variations",
                "HTTP method switching"
            ],
            "ModSecurity": [
                "Case variations",
                "HTML entity encoding",
                "Comment injection",
                "Line terminator variations"
            ],
            "Generic WAF": [
                "URL encoding",
                "HTML entity encoding",
                "Case variations",
                "Comment injection",
                "Multi-part request body"
            ]
        }
        
        # Get bypass techniques for detected WAF
        techniques = bypass_techniques.get(waf_type, bypass_techniques["Generic WAF"])
        
        # Calculate bypass potential
        vuln_type = vulnerability.get("type", "")
        bypass_potential = 0.5  # Default medium potential
        
        if vuln_type == "XSS":
            bypass_potential = 0.7  # Higher potential for XSS
        elif vuln_type == "SQLi":
            bypass_potential = 0.6  # Medium-high for SQLi
        elif vuln_type == "RCE":
            bypass_potential = 0.4  # Lower for RCE due to stricter rules
            
        # Adjust based on WAF type
        waf_factor = self.waf_impact_factors.get(waf_type, 0.85)
        bypass_potential *= (2 - waf_factor)  # Invert WAF effectiveness for bypass potential
        
        # Normalize to 0-1 range
        bypass_potential = min(1.0, max(0.0, bypass_potential))
        
        return {
            "bypass_potential": round(bypass_potential, 2),
            "bypass_techniques": techniques,
            "waf_type": waf_type,
            "recommendations": self._generate_bypass_recommendations(waf_type, vuln_type)
        }
        
    def _generate_bypass_recommendations(self, waf_type: str, vuln_type: str) -> List[str]:
        """Generate WAF bypass recommendations based on WAF type and vulnerability"""
        recommendations = []
        
        if vuln_type == "XSS":
            recommendations.extend([
                "Try different encoding variations (URL, HTML, Unicode)",
                "Use JavaScript event handlers that may not be monitored",
                "Split payload across multiple parameters",
                "Use template literals instead of quotes"
            ])
        elif vuln_type == "SQLi":
            recommendations.extend([
                "Use case variations for SQL keywords",
                "Try alternative syntax for SQL statements",
                "Use CHAR() function to encode strings",
                "Use timing-based techniques for blind injection"
            ])
        elif vuln_type == "CSRF":
            recommendations.extend([
                "Use different Content-Type headers",
                "Try different request methods",
                "Embed payload in JSON body"
            ])
            
        # Add WAF-specific recommendations
        if waf_type == "Cloudflare":
            recommendations.append("Use non-standard headers to bypass inspection")
            recommendations.append("Try multi-part form data instead of standard POST")
        elif waf_type == "AWS WAF":
            recommendations.append("Use nested JSON objects to hide payloads")
            recommendations.append("Try parameter pollution techniques")
            
        return recommendations
