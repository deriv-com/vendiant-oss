from fastapi import APIRouter, HTTPException, Request, Query, Body
from typing import Optional
import logging
import time
import os
import json
from dotenv import load_dotenv

# Import database services
from db_service import get_vulnerabilities_for_domain, AiAnalyticsService
from scan_health_notifier import notify_external_api_failure

router = APIRouter()

# AI insights caching is now handled by database (ai_analytics table) using vulnerability_count

def _llm_api_base() -> str:
    """OpenAI-compatible base URL from OPENAI_BASE_URL (OpenAI, LiteLLM, vLLM, ...)."""
    base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    if not base.endswith("/v1"):
        base = f"{base}/v1"
    return base


def get_ai_client_config():
    """Get AI client configuration and create OpenAI client for any OpenAI-compatible endpoint."""
    # Reload environment variables (repo root .env, then Dashboard/.env)
    routes_dir = os.path.dirname(__file__)
    for env_path in (
        os.path.join(routes_dir, '..', '..', '.env'),
        os.path.join(routes_dir, '..', '.env'),
    ):
        if os.path.exists(env_path):
            load_dotenv(env_path, override=True)
    
    api_base = _llm_api_base()
    
    # API key: use OPENAI_API_KEY (required)
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise Exception("No API key found. Please set OPENAI_API_KEY.")
    
    # Model: use the Responses API web-search capable model by default.
    model_name = os.getenv('OPENAI_MODEL_NAME', 'gpt-5.6-luna')
    
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=api_base)
    
    logging.info(f"Using LLM API at {api_base} with model: {model_name}")
    
    return client, model_name

def extract_response_text(response) -> str:
    """Extract plain text from an OpenAI Responses API response."""
    output_text = getattr(response, "output_text", None)
    if output_text:
        return output_text

    text_parts = []
    for output_item in getattr(response, "output", []) or []:
        content_items = output_item.get("content", []) if isinstance(output_item, dict) else getattr(output_item, "content", [])
        for content_item in content_items or []:
            text = content_item.get("text") if isinstance(content_item, dict) else getattr(content_item, "text", None)
            if text:
                text_parts.append(text)

    return "\n".join(text_parts)

def parse_ai_response(ai_response, vendor_name, overall_score, grade, total_vulnerabilities, critical_count, high_count):
    """Parse AI response into structured insights"""
    import re
    
    vendor_overview = ""
    security_posture = ""
    next_steps = []
    
    # Try to extract sections using regex patterns (more flexible)
    # Look for VENDOR_OVERVIEW section
    overview_match = re.search(r'(?:VENDOR[_\s]OVERVIEW|Vendor\s+Overview)[:\s]*\n*(.*?)(?=(?:SECURITY[_\s]POSTURE|Security\s+Posture|NEXT[_\s]STEPS|Next\s+Steps)|$)', ai_response, re.IGNORECASE | re.DOTALL)
    if overview_match:
        vendor_overview = overview_match.group(1).strip()
    
    # Look for SECURITY_POSTURE section
    posture_match = re.search(r'(?:SECURITY[_\s]POSTURE|Security\s+Posture|Overall\s+Security\s+Posture)[:\s]*\n*(.*?)(?=(?:NEXT[_\s]STEPS|Next\s+Steps)|$)', ai_response, re.IGNORECASE | re.DOTALL)
    if posture_match:
        security_posture = posture_match.group(1).strip()
    
    # Look for NEXT_STEPS section
    steps_match = re.search(r'(?:NEXT[_\s]STEPS|Next\s+Steps)[:\s]*\n*(.*?)$', ai_response, re.IGNORECASE | re.DOTALL)
    if steps_match:
        steps_text = steps_match.group(1).strip()
        # Split by newlines and extract steps
        for line in steps_text.split('\n'):
            line = line.strip()
            if line:
                # Remove numbering, bullets, and markdown formatting
                cleaned_step = re.sub(r'^\d+[\.\)]\s*', '', line)  # Remove "1. " or "1) "
                cleaned_step = re.sub(r'^[-•]\s*', '', cleaned_step)  # Remove bullets (- and •)
                cleaned_step = re.sub(r'^\*+\s*', '', cleaned_step)  # Remove leading asterisks (* or **)
                cleaned_step = re.sub(r'\*\*(.*?)\*\*', r'\1', cleaned_step)  # Remove **bold** formatting
                cleaned_step = re.sub(r'\*(.*?)\*', r'\1', cleaned_step)  # Remove *italic* formatting
                cleaned_step = cleaned_step.strip()
                if cleaned_step and len(cleaned_step) > 10:  # Ignore very short lines
                    next_steps.append(cleaned_step)
    
    # Clean up the extracted content
    if vendor_overview:
        vendor_overview = re.sub(r'https?://[^\s\)]+', '', vendor_overview)
        vendor_overview = re.sub(r'\([^)]*(?:https?://|\.com|source=|utm_)[^)]*\)', '', vendor_overview)
        vendor_overview = re.sub(r'\[[^\]]*\.(?:com|org|net|edu|gov)[^\]]*\]', '', vendor_overview)
        vendor_overview = re.sub(r'\(\s*\)', '', vendor_overview)
        vendor_overview = re.sub(r'\*\*(.*?)\*\*', r'\1', vendor_overview)
        vendor_overview = re.sub(r'\s+', ' ', vendor_overview).strip()
    
    if security_posture:
        # Remove leading asterisks and markdown formatting first
        security_posture = re.sub(r'^\s*\*+\s*', '', security_posture)  # Remove leading asterisks at start
        security_posture = re.sub(r'^[\s]*[-•*]\s*', '', security_posture, flags=re.MULTILINE)  # Remove bullets on each line
        security_posture = re.sub(r'\*\*(.*?)\*\*', r'\1', security_posture)  # Remove **bold** formatting
        security_posture = re.sub(r'\*(.*?)\*', r'\1', security_posture)  # Remove *italic* formatting
        # Remove URLs and sources
        security_posture = re.sub(r'https?://[^\s\)]+', '', security_posture)
        security_posture = re.sub(r'\([^)]*(?:https?://|\.com|source=|utm_)[^)]*\)', '', security_posture)
        security_posture = re.sub(r'\[[^\]]*\.(?:com|org|net|edu|gov)[^\]]*\]', '', security_posture)
        security_posture = re.sub(r'\(\s*\)', '', security_posture)
        # Clean up whitespace
        security_posture = re.sub(r'\s+', ' ', security_posture).strip()
    
    # No fallback content - AI must generate all sections
    # If parsing fails, return empty strings/lists to indicate failure
    return vendor_overview, security_posture, next_steps

def generate_template_insights(vendor_name, domain, overall_score, grade, total_vulnerabilities, severity_breakdown, score_summary, subdomains_count):
    """Generate deterministic fallback insights when AI generation is unavailable."""
    critical_count = severity_breakdown.get('Critical', 0)
    high_count = severity_breakdown.get('High', 0)
    medium_count = severity_breakdown.get('Medium', 0)
    low_count = severity_breakdown.get('Low', 0)

    weakest_categories = sorted(score_summary.items(), key=lambda item: item[1])[:3] if score_summary else []
    weakest_text = ", ".join(f"{category} ({score})" for category, score in weakest_categories) or "the lowest scoring security categories"

    return {
        "vendor_overview": f"{vendor_name} is associated with {domain}. This fallback overview is based on the available vendor security assessment data.",
        "overall_security_posture": (
            f"{vendor_name} has an overall security score of {overall_score}/950 with grade {grade}. "
            f"The assessment found {total_vulnerabilities} vulnerabilities, including {critical_count} critical, "
            f"{high_count} high, {medium_count} medium, and {low_count} low severity findings. "
            f"Priority review should focus on {weakest_text}, with {subdomains_count} subdomains included in the assessed attack surface."
        ),
        "next_steps": [
            "Prioritize remediation of critical and high severity vulnerabilities.",
            "Review the lowest scoring security categories and define owners for each remediation track.",
            "Validate exposed subdomains and remove or restrict unnecessary public services.",
            "Re-run the security assessment after remediation to confirm risk reduction.",
            "Document residual risks and target dates for medium and low severity findings.",
            "Monitor vendor security posture continuously for new exposures or regressions."
        ]
    }


@router.post('/api/ai-insights/generate')
async def generate_ai_insights(data: dict = Body(...)):
    """Generate AI-powered security insights for a vendor
    
    This endpoint fetches vulnerabilities directly from the database and uses
    AiAnalyticsService with vulnerability_count to cache summaries. When vulnerability
    count increases, the summary is regenerated.
    """
    try:
        logging.info(f"AI Insights request received for domain: {data.get('domain') if data else 'No data'}")
        
        domain = data.get('domain')
        vendor_data = data.get('vendor', {})
        scores_data = data.get('scores', [])
        subdomains_count = data.get('subdomains_count', 0)
        force_refresh = data.get('force_refresh', False)
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Ensure vendor_data is a dict (handle case where it might be a string or None)
        if not isinstance(vendor_data, dict):
            if isinstance(vendor_data, str):
                try:
                    import json
                    vendor_data = json.loads(vendor_data)
                except:
                    vendor_data = {}
            else:
                vendor_data = {}
        
        # Ensure scores_data is a list (handle case where it might be a string or None)
        if not isinstance(scores_data, list):
            if isinstance(scores_data, str):
                try:
                    import json
                    scores_data = json.loads(scores_data)
                except:
                    scores_data = []
            else:
                scores_data = []
        
        # Fetch vulnerabilities directly from database
        logging.info(f"Fetching vulnerabilities from database for {domain}")
        vulnerabilities = get_vulnerabilities_for_domain(domain)
        
        # Calculate vulnerability summary from database vulnerabilities
        total_vulnerabilities = len(vulnerabilities)
        logging.info(f"Found {total_vulnerabilities} vulnerabilities for {domain}")
        severity_breakdown = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', '').capitalize()
                if severity in severity_breakdown:
                    severity_breakdown[severity] += 1
                else:
                    severity_breakdown['Info'] += 1
        
        critical_count = severity_breakdown.get('Critical', 0)
        high_count = severity_breakdown.get('High', 0)
        medium_count = severity_breakdown.get('Medium', 0)
        low_count = severity_breakdown.get('Low', 0)
        
        # Prepare data for AI analysis
        vendor_name = vendor_data.get('name') or vendor_data.get('vendor_name', domain) if isinstance(vendor_data, dict) else domain
        overall_score = vendor_data.get('overall_score', 0) if isinstance(vendor_data, dict) else 0
        grade = vendor_data.get('grade', 'N/A') if isinstance(vendor_data, dict) else 'N/A'
        
        # Check if there are any vulnerabilities to analyze
        if total_vulnerabilities == 0:
            logging.info(f"No vulnerabilities found for {domain}, skipping AI insights generation")
            return {
                'status': 'success',
                'message': 'No vulnerabilities found - AI insights will be generated once security scan completes',
                'insights': None,
                'no_vulnerabilities': True
            }
        
        # Score breakdown by category
        score_summary = {}
        # Handle both array and dict formats for scores_data
        if isinstance(scores_data, dict):
            # If scores_data is a dict, convert to list format
            scores_data = [scores_data]
        elif not isinstance(scores_data, list):
            scores_data = []
        
        for score_item in scores_data:
            if isinstance(score_item, dict):
                category = score_item.get('score_category', score_item.get('category', 'Unknown'))
                score = score_item.get('score', 0)
                score_summary[category] = score
        
        # Calculate risk level
        risk_level = "Low Risk"
        if overall_score < 200:
            risk_level = "High Risk"
        elif overall_score < 400:
            risk_level = "Medium-High Risk"
        elif overall_score < 600:
            risk_level = "Medium Risk"
        elif overall_score < 800:
            risk_level = "Low-Medium Risk"
        
        # Initialize AiAnalyticsService for database-backed caching
        ai_service = AiAnalyticsService()
        
        # Always check vulnerability count first - only regenerate if count increased
        # This applies even when force_refresh is requested (no redundant API calls)
        cached_summary = ai_service.get_or_reuse_summary(domain, total_vulnerabilities)
        if cached_summary:
            if force_refresh:
                logging.info(f"Force refresh requested for {domain}, but vulnerability count unchanged ({total_vulnerabilities}) - returning cached summary")
            else:
                logging.info(f"Returning cached AI summary for {domain} (vulnerability count: {total_vulnerabilities})")
            
            # Parse the cached summary JSON
            try:
                import json
                # Ensure cached_summary is a dict
                if not isinstance(cached_summary, dict):
                    logging.warning(f"Cached summary is not a dict for {domain}, regenerating...")
                else:
                    insights = json.loads(cached_summary.get('ai_summary', '{}'))
                    return {
                        'status': 'success',
                        'insights': insights,
                        'cached': True
                    }
            except Exception as e:
                logging.warning(f"Failed to parse cached summary for {domain}: {e}, regenerating...")
        
        # Prepare vulnerability details for the prompt (top critical/high severity issues)
        critical_high_vulns = [v for v in vulnerabilities if isinstance(v, dict) and v.get('severity', '').capitalize() in ['Critical', 'High']]
        vulnerability_details = ""
        if critical_high_vulns:
            vulnerability_details = "\n\nKey Security Issues Found:\n"
            for vuln in critical_high_vulns[:10]:  # Limit to top 10 for prompt size
                if isinstance(vuln, dict):
                    category = vuln.get('category', vuln.get('score_category', 'Unknown'))
                    title = vuln.get('title', 'Unknown issue')
                    severity = vuln.get('severity', 'Unknown')
                    vulnerability_details += f"- [{severity}] {category}: {title}\n"
        
        # Prepare prompt for AI analysis
        prompt = f"""Analyze this vendor security assessment and provide insights in THREE sections:

DATA:
Vendor: {vendor_name} | Domain: {domain}
Score: {overall_score}/950 ({grade}) | Risk: {risk_level}
Vulnerabilities: Critical={critical_count}, High={high_count}, Medium={medium_count}, Low={low_count}, Total={total_vulnerabilities}
{vulnerability_details}
Security Scores: {', '.join([f"{cat}={score}" for cat, score in score_summary.items()])}
Subdomains: {subdomains_count}

Provide your analysis in this format:

VENDOR_OVERVIEW:
[2-3 sentences about what {vendor_name} does as a business - their products, services, industry, target market. DO NOT mention security. Focus on business only.]

SECURITY_POSTURE:
[Comprehensive paragraph analyzing the specific vulnerabilities, severity distribution, security categories affected, and business risk implications. Reference actual scores and vulnerability types. Write in narrative prose, no bullet points.]

NEXT_STEPS:
1. [First specific recommendation based on actual findings]
2. [Second specific recommendation]
3. [Third specific recommendation]
4. [Fourth specific recommendation]
5. [Fifth specific recommendation]
6. [Sixth specific recommendation]

CRITICAL: You MUST complete ALL three sections (VENDOR_OVERVIEW, SECURITY_POSTURE, and NEXT_STEPS) in full. Do NOT stop mid-sentence. Each NEXT_STEPS item must be a complete, actionable recommendation. Ensure all 6 steps are fully written out before ending your response."""
        
        try:
            # Use shared AI client configuration
            logging.info(f"Attempting AI generation for {vendor_name}")
            client, model_name = get_ai_client_config()
            
            request_params = {
                "model": model_name,
                "instructions": "You are a cybersecurity expert analyst providing detailed security assessments for vendor risk management.",
                "input": prompt,
                "tools": [{"type": "web_search"}],
                "temperature": 0.2,
                "max_output_tokens": 4000
            }

            logging.info(f"Making AI API call with model: {model_name}")
            response = client.responses.create(**request_params)
            logging.info("AI API call successful")

            status = getattr(response, "status", None)
            incomplete_details = getattr(response, "incomplete_details", None)
            finish_reason = getattr(incomplete_details, "reason", None) or status
            if status == 'incomplete':
                logging.warning(f"AI response was incomplete! reason={finish_reason}. Consider increasing max_output_tokens.")

            ai_response = extract_response_text(response)
            
            # Log the full AI response for debugging
            logging.info(f"Full AI response ({len(ai_response) if ai_response else 0} chars, finish_reason: {finish_reason}): {ai_response}")
            
            # Parse the AI response using shared function
            vendor_overview, security_posture, next_steps = parse_ai_response(
                ai_response, vendor_name, overall_score, grade, 
                total_vulnerabilities, critical_count, high_count
            )
            
            logging.info(f"Parsed AI response - Overview: {len(vendor_overview)} chars, Posture: {len(security_posture)} chars, Steps: {len(next_steps)} items")
            
            # Calculate sources data
            sources = {
                "domains": subdomains_count + 1,  # Include main domain  # Estimate based on subdomains
                "risks": total_vulnerabilities
            }
            
            insights = {
                "vendor_overview": vendor_overview,
                "overall_security_posture": security_posture,
                "next_steps": next_steps[:6],  # Limit to 6 steps
                "sources": sources,
                "last_generated": time.strftime('%B %d, %Y', time.gmtime())
            }
            
            # Save to database using AiAnalyticsService with vulnerability_count
            # This ensures the summary is regenerated when vulnerability count changes
            import json
            ai_summary_json = json.dumps(insights)
            try:
                result_id = ai_service.upsert_summary(
                    domain=domain,
                    vendor_name=vendor_name,
                    ai_summary=ai_summary_json,
                    vulnerability_count=total_vulnerabilities
                )
                if result_id:
                    logging.info(f"Successfully saved AI summary to database for {domain} (ID: {result_id}) with vulnerability_count: {total_vulnerabilities}")
                else:
                    logging.error(f"Failed to save AI summary to database for {domain} - upsert_summary returned None")
            except Exception as save_error:
                logging.error(f"Exception while saving AI summary to database for {domain}: {save_error}")
                import traceback
                logging.error(f"Traceback: {traceback.format_exc()}")
            
            return {
                'status': 'success',
                'insights': insights
            }
            
        except Exception as ai_error:
            import traceback
            logging.error(f"AI generation error: {str(ai_error)}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            logging.warning(f"AI failed for {vendor_name}, unable to generate insights")

            # Extract HTTP status code if available (openai SDK exposes it on the exception)
            ai_status_code = getattr(ai_error, 'status_code', None)
            notify_external_api_failure("OpenAI", str(ai_error), domain=domain, status_code=ai_status_code)

            return {
                'status': 'error',
                'message': 'Unable to generate insights',
                'insights': None,
                'error': str(ai_error)
            }
            
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logging.error(f"Error generating AI insights: {str(e)}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to generate insights: {str(e)}'
        )
