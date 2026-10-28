#!/usr/bin/env python3
import sys
import os
import logging
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass

# Configure logging
# Add custom integrations path for logger
_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

@dataclass
class SeverityWeights:
    """Severity weights for vulnerability scoring"""
    CRITICAL: int = 100
    HIGH: int = 75
    MEDIUM: int = 50
    LOW: int = 25
    INFO: int = 0

@dataclass
class CategoryWeights:
    """Base category weights for overall scoring (percentages)"""
    WEBSITE: float = 0.20      # 20%
    DOMAIN_REPUTATION: float = 0.20  # 20%
    ENCRYPTION: float = 0.25   # 25%
    NETWORK: float = 0.15      # 15%
    EMAIL: float = 0.10        # 10%
    DNS: float = 0.10          # 10%

class UnifiedScoringSystem:
    """Unified scoring system for all security scans"""
    
    def __init__(self):
        self.base_score = 950
        self.severity_weights = SeverityWeights()
        self.category_weights = CategoryWeights()
    
    def calculate_individual_scan_score(self, vulnerabilities: List[Dict], scan_category: str) -> Dict[str, Any]:
        """
        Calculate score for an individual scan category
        
        Args:
            vulnerabilities: List of vulnerability dictionaries with 'severity' key
            scan_category: Category name (WEBSITE, DOMAIN_REPUTATION, etc.)
            
        Returns:
            Dict with score, deductions, and statistics
        """
        # Count vulnerabilities by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0, 
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate total deduction using severity weights
        total_deduction = 0
        deduction_breakdown = {}
        
        for severity, count in severity_counts.items():
            if count > 0:
                weight = getattr(self.severity_weights, severity, 0)
                deduction = count * weight
                total_deduction += deduction
                deduction_breakdown[severity] = deduction
        
        # Calculate final score
        final_score = max(0, self.base_score - total_deduction)
        
        # Calculate vulnerability density for dynamic weighting
        total_vulnerabilities = sum(severity_counts.values())
        critical_high_count = severity_counts['CRITICAL'] + severity_counts['HIGH']
        
        return {
            'score': final_score,
            'max_score': self.base_score,
            'total_deduction': total_deduction,
            'deduction_breakdown': deduction_breakdown,
            'severity_counts': severity_counts,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_high_count': critical_high_count,
            'percentage': round((final_score / self.base_score) * 100, 2)
        }
    
    def calculate_dynamic_weights(self, scan_results: Dict[str, Dict]) -> Dict[str, float]:
        """
        Calculate dynamic weights based on vulnerability counts and severity
        
        Args:
            scan_results: Dictionary of scan results by category
            
        Returns:
            Dictionary of adjusted weights by category
        """
        base_weights = {
            'WEBSITE': self.category_weights.WEBSITE,
            'DOMAIN_REPUTATION': self.category_weights.DOMAIN_REPUTATION,
            'ENCRYPTION': self.category_weights.ENCRYPTION,
            'NETWORK': self.category_weights.NETWORK,
            'EMAIL': self.category_weights.EMAIL,
            'DNS': self.category_weights.DNS
        }
        
        # Calculate vulnerability density and severity factors for each category
        category_factors = {}
        
        for category, results in scan_results.items():
            if category not in base_weights:
                continue
                
            total_vulns = results.get('total_vulnerabilities', 0)
            critical_high = results.get('critical_high_count', 0)
            
            # Vulnerability density factor (more vulnerabilities = higher weight)
            density_factor = min(1.5, 1.0 + (total_vulns * 0.02))  # Cap at 1.5x
            
            # Severity factor (more critical/high = higher weight)
            severity_factor = min(1.3, 1.0 + (critical_high * 0.05))  # Cap at 1.3x
            
            # Combined factor
            combined_factor = (density_factor + severity_factor) / 2
            category_factors[category] = combined_factor
        
        # Apply factors to base weights
        adjusted_weights = {}
        total_adjustment = 0
        
        for category, base_weight in base_weights.items():
            if category in category_factors:
                factor = category_factors[category]
                adjusted_weight = base_weight * factor
                adjusted_weights[category] = adjusted_weight
                total_adjustment += adjusted_weight
            else:
                adjusted_weights[category] = base_weight
                total_adjustment += base_weight
        
        # Normalize to ensure weights sum to 1.0
        if total_adjustment > 0:
            for category in adjusted_weights:
                adjusted_weights[category] = adjusted_weights[category] / total_adjustment
        
        logger.info(f"Dynamic weight adjustments:")
        for category, weight in adjusted_weights.items():
            base_weight = base_weights[category]
            change = ((weight - base_weight) / base_weight) * 100
            logger.info(f"  {category}: {weight:.3f} ({change:+.1f}% from base {base_weight:.3f})")
        
        return adjusted_weights
    
    def calculate_overall_score(self, scan_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Calculate overall weighted score across all categories
        
        Args:
            scan_results: Dictionary of individual scan results by category
            
        Returns:
            Dictionary with overall score and breakdown
        """
        # Calculate dynamic weights
        dynamic_weights = self.calculate_dynamic_weights(scan_results)
        
        # Calculate weighted score
        weighted_total = 0
        category_contributions = {}
        
        for category, results in scan_results.items():
            if category in dynamic_weights:
                category_score = results.get('score', self.base_score)
                weight = dynamic_weights[category]
                contribution = category_score * weight
                weighted_total += contribution
                category_contributions[category] = {
                    'score': category_score,
                    'weight': weight,
                    'contribution': contribution,
                    'percentage': round((category_score / self.base_score) * 100, 2)
                }
        
        overall_score = round(weighted_total)
        
        # No calibration - use the actual calculated score
        logger.info(f"Overall weighted score calculated: {overall_score}/950 ({(overall_score/self.base_score)*100:.1f}%)")
        
        return {
            'overall_score': overall_score,
            'max_score': self.base_score,
            'percentage': round((overall_score / self.base_score) * 100, 2),
            'category_contributions': category_contributions,
            'dynamic_weights': dynamic_weights,
            'calibration_applied': False,
            'calibration_factor': 1.0,
            'target_score': None,
            'within_target_range': True
        }
    
    def get_category_severity_weights(self, category: str) -> Dict[str, int]:
        """Get severity weights for a specific category (for backward compatibility)"""
        return {
            'CRITICAL': self.severity_weights.CRITICAL,
            'HIGH': self.severity_weights.HIGH,
            'MEDIUM': self.severity_weights.MEDIUM,
            'LOW': self.severity_weights.LOW,
            'INFO': self.severity_weights.INFO
        }
    
    def get_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score >= 800:
            return 'Low'
        elif score >= 600:
            return 'Medium'
        elif score >= 400:
            return 'High'
        else:
            return 'Critical'

# Global instance for use across modules
unified_scoring = UnifiedScoringSystem()

def get_unified_scoring() -> UnifiedScoringSystem:
    """Get the global unified scoring instance"""
    return unified_scoring

# Convenience functions for individual modules
def calculate_scan_score(vulnerabilities: List[Dict], category: str) -> Dict[str, Any]:
    """Calculate score for a scan category"""
    return unified_scoring.calculate_individual_scan_score(vulnerabilities, category)

def get_severity_weights(category: str = None) -> Dict[str, int]:
    """Get severity weights for scoring"""
    return unified_scoring.get_category_severity_weights(category)

def calculate_overall_vendor_score(scan_results: Dict[str, Dict]) -> Dict[str, Any]:
    """Calculate overall vendor score from all scan results"""
    return unified_scoring.calculate_overall_score(scan_results)

def update_vendor_overall_score_after_scan(domain: str, scan_format: str = 'individual_scan') -> bool:
    """
    Calculate and update vendor overall score in database after a scan completes
    
    Args:
        domain: Vendor domain
        scan_format: Type of scan that triggered this update (default: 'individual_scan')
    
    Returns:
        Boolean indicating success
    """
    try:
        # Import here to avoid circular imports
        dashboard_dir = os.path.join(os.environ.get("VENDIANT_APP_ROOT", "/app"), "Dashboard")
        if dashboard_dir not in sys.path:
            sys.path.append(dashboard_dir)
        from db_service import update_vendor_overall_score, get_scores_for_domain, get_vulnerabilities_for_domain
        
        # Get all existing scores and vulnerabilities for this domain
        scores_data = get_scores_for_domain(domain)
        vulnerabilities_data = get_vulnerabilities_for_domain(domain)
        
        # Organize by category
        category_scores = {}
        category_vulnerabilities = {}
        
        # Process scores
        for score_item in scores_data:
            category = score_item.get('score_category', score_item.get('category', 'Unknown'))
            category_scores[category.upper()] = {
                'score': score_item.get('score', 950),
                'updated_at': score_item.get('updated_at'),
                'max_score': 950
            }
        
        # Process vulnerabilities by category
        for vuln in vulnerabilities_data:
            category = vuln.get('category', 'Unknown').upper()
            if category not in category_vulnerabilities:
                category_vulnerabilities[category] = []
            category_vulnerabilities[category].append(vuln)
        
        # Create complete scan results structure
        complete_scan_results = {}
        
        # Map database categories to unified scoring categories
        category_mapping = {
            'WEBSITE': 'WEBSITE',
            'DOMAIN_REPUTATION': 'DOMAIN_REPUTATION', 
            'ENCRYPTION': 'ENCRYPTION',
            'NETWORK': 'NETWORK',
            'EMAIL': 'EMAIL',
            'DNS': 'DNS'
        }
        
        for db_category, unified_category in category_mapping.items():
            if db_category in category_scores:
                # Use the stored individual score instead of recalculating from vulnerabilities
                stored_score = category_scores[db_category]['score']
                vulns = category_vulnerabilities.get(db_category, [])
                
                # Get vulnerability counts for metadata
                severity_counts = {
                    'CRITICAL': 0,
                    'HIGH': 0, 
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 0
                }
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'INFO').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                total_vulnerabilities = sum(severity_counts.values())
                critical_high_count = severity_counts['CRITICAL'] + severity_counts['HIGH']
                
                # Use stored score with vulnerability metadata
                complete_scan_results[unified_category] = {
                    'score': stored_score,
                    'max_score': 950,
                    'total_deduction': 950 - stored_score,
                    'total_vulnerabilities': total_vulnerabilities,
                    'critical_high_count': critical_high_count,
                    'percentage': round((stored_score / 950) * 100, 2),
                    'severity_counts': severity_counts
                }
            else:
                # Category not scanned yet, use perfect score
                complete_scan_results[unified_category] = {
                    'score': 950,
                    'max_score': 950,
                    'total_deduction': 0,
                    'total_vulnerabilities': 0,
                    'critical_high_count': 0,
                    'percentage': 100.0
                }
        
        # Calculate overall weighted score
        overall_result = unified_scoring.calculate_overall_score(complete_scan_results)
        
        # Pass scan_format explicitly. It was previously omitted here, which
        # made update_vendor_overall_score inherit whatever label the last row
        # for this domain carried -- so scan_format stopped identifying what
        # actually produced the row.
        success = update_vendor_overall_score(
            domain, overall_result['overall_score'], scan_format=scan_format
        )
        
        if success:
            logger.info(f"AUTO-UPDATED OVERALL SCORE for {domain}: {overall_result['overall_score']}/950 ({overall_result['percentage']}%) with scan_format={scan_format}")
        
        return success
        
    except Exception as e:
        logger.error(f"Error auto-updating overall score for {domain}: {e}")
        return False 