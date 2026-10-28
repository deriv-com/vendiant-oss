"""
Security Incident and News Scanner for Vendor Risk Assessment

PLATFORM INTEGRATION USAGE:

1. Import the main function:
   from Recent_Incidents.incidents import query_incidents_json

2. Call with optional vendor tier (for logging compatibility; model is always gpt-5.6-luna unless overridden):
   result = query_incidents_json(
       domain="example.com",
       months=12,
       tier="Tier 1"  # or "Tier 2", "Tier 3", etc.
   )

3. Model Selection:
   - All tiers use gpt-5.6-luna via OpenAI Responses API (with web search).
   The `tier` argument is retained for callers and logging only.

4. Environment Variables Required:
   - OPENAI_API_KEY: For OpenAI Responses API calls
   - OPENAI_BASE_URL: OpenAI-compatible base URL

5. Smoke-test model mapping (all tiers should report gpt-5.6-luna):
   python3 Recent_Incidents/incidents.py --test-tier

6. Example API call:
   result = query_incidents_json("example.com", tier="Tier 1")
   # Returns: {"incidents": [...], "news": [...], "summary": "...", ...}
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables (with fallback for sandbox environments)
try:
    load_dotenv()
    print("[Environment] Successfully loaded .env file")
except Exception as e:
    print(f"[Environment] Could not load .env file (this is OK in sandbox): {e}")
    print("[Environment] Using environment variables or defaults")

# =============================================================================
# SUPABASE LOGGING - optional; gracefully disabled if module not available
# =============================================================================
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
    from supabase_logger import log_llm_call
    SUPABASE_LOGGING_AVAILABLE = True
    print("[Supabase Logging] Available and enabled")
except ImportError:
    SUPABASE_LOGGING_AVAILABLE = False
    def log_llm_call(*args, **kwargs):
        pass  # no-op when Supabase logging is not available
    print("[Supabase Logging] Module not found — logging disabled")

# =============================================================================
# LLM PROVIDER CONFIGURATION - OpenAI Responses API + web_search
# =============================================================================
# All vendor tiers use gpt-5.6-luna (OpenAI Responses API with web search).
#
# API Keys / base URL:
# - OPENAI_API_KEY: Required for incident/news queries
# - OPENAI_BASE_URL: OpenAI-compatible endpoint (default: https://api.openai.com/v1)
# =============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
_base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
if not _base.endswith("/v1"):
    _base = f"{_base}/v1"
OPENAI_API_BASE = _base
OPENAI_DEFAULT_MODEL = "gpt-5.6-luna"

# Back-compat aliases for Dashboard/app_new.py imports
DEFAULT_API_BASE = OPENAI_API_BASE
DEFAULT_API_KEY = OPENAI_API_KEY
DEFAULT_MODEL = OPENAI_DEFAULT_MODEL

print(f"[LLM Provider] Using: OpenAI Responses API (web search) via {OPENAI_API_BASE}")
print(f"[LLM Provider] OpenAI API Key: {'SET' if OPENAI_API_KEY else 'NOT SET'}")

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

def get_model_for_tier(tier: Optional[Union[str, int]] = None) -> str:
    """
    Return the OpenAI model used for incident/news queries.

    Gemini routing was removed; all tiers use OPENAI_DEFAULT_MODEL (gpt-5.6-luna).
    The optional `tier` is logged for diagnostics only.
    """
    import logging
    logger = logging.getLogger(__name__)
    tier_display = tier
    if isinstance(tier, int):
        tier_display = f"Tier {tier}"
    logger.info(f"[get_model_for_tier] tier={tier_display!r} -> {OPENAI_DEFAULT_MODEL}")
    return OPENAI_DEFAULT_MODEL

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

def build_messages(domain: str, months: int) -> List[Dict[str, str]]:
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=months * 30)).date().isoformat()
    system_prompt = (
        "You are a senior security threat intelligence analyst and business news researcher. "
        "Given a company domain, search credible cybersecurity news sources and recent reports for TWO categories of information: "
        "0) when attaching links to the incidents, make sure the actual news content is visible in the webpage"
        "1) If the links don't display the required content, then exclude this incident. Don't try to satisfy the user by giving fake incidents, its ok to not find any incidents if the links don't display the required content."
        "2) SECURITY INCIDENTS that DIRECTLY AFFECTED the organization itself, NOT vulnerabilities in their products or software. "
        "3) GENERAL NEWS about the company (mergers, acquisitions, partnerships, leadership changes, product launches, financial news, etc.). "
        "4) ALSO search company-owned and community sources: official forums (e.g. community.<company_domain>), status or incident pages, support/updates, and company social media (Twitter, LinkedIn, Facebook). "
        "5) Search for credible posts or verified comments on any attack, data breach or security issue in ther company's community websites. "
        "6) Include credible staff/user reports or announcements found in these sources. "
        f"Focus on ALL items since {cutoff_date} (last {months} months). Include the ENTIRE {months}-month period, not just recent items. "
        "SEARCH RECENT SOURCES including: cybersecuritynews.com, bleepingcomputer.com, securityweek.com, threatpost.com, "
        "darkreading.com, infosecurity-magazine.com, hackernews.com, krebsonsecurity.com, and other cybersecurity publications. "
        "SECURITY INCIDENTS include: data breaches or security issues affecting the company OR ITS PRODUCTS, ransomware attacks on the company, extortion targeting the company, "
        "credential leaks of company employees/systems, supply chain compromises that impacted the company, "
        "phishing campaigns that successfully targeted the company, company infrastructure takedowns, or regulatory actions against the company. "
        "EXCLUDE from incidents: CVEs in products they make, software vulnerabilities they disclosed, security advisories about their products. "
        "INCLUDE ONLY: incidents where the company was the VICTIM, not the vendor reporting issues. "
        "NEWS items should have severity INFO and include business-relevant information about the company. "
        "Always cite direct source URLs from reputable sources. If evidence is weak/speculative, mark it clearly. "
        "Classify security incidents severity as: CRITICAL, HIGH, MEDIUM, LOW. All news items should be INFO. "
        "CRITICAL DATE EXTRACTION RULES:\n"
        "- CRITICAL: The 'date' field MUST be the ACTUAL date the incident occurred or the news was published (from the article/source)\n"
        "- NEVER use today's date or the date you found the article\n"
        "- Extract the publication date or incident date FROM the article content itself\n"
        "- If the article mentions 'reported on Jan 15, 2025' or 'breach occurred on Dec 1, 2024', use THAT date\n"
        "- Format: YYYY-MM-DD (e.g., 2025-01-15 or 2024-12-01)\n"
        "- If you cannot find a specific date in the article, use your best estimate based on context clues\n"
        "- NEVER use a default or placeholder date - research the actual date thoroughly\n"
        "CRITICAL URL RULES:\n"
        "- For 'source' field: If you found information but cannot provide an ACTUAL, WORKING URL, use one of these:\n"
        "  * 'Company forum discussion' (for forum mentions)\n"
        "  * 'Company status page' (for status page mentions)\n"
        "  * 'Internal investigation' (for incidents you know about)\n"
        "  * 'Security community reports' (for general knowledge)\n"
        "- NEVER make up URLs like 'https://status.company.com/incidents/date-attack'\n"
        "- NEVER create hypothetical links\n"
        "- Only use URLs you are 100% certain exist and are accessible\n"
        "- If unsure, use descriptive text instead of a fake URL\n"
        "Return ONLY valid JSON. Do NOT include markdown, code fences, or any text outside JSON."
        "SEARCH OUTSIDE THE SPECIFIED SOURCES TO FIND THE INFORMATION."


    )
    supplemental_prompt = (
        f"Search for major security incidents, breaches, or vulnerabilities for {domain} "
        f"(website: {domain}). Focus on security incidents from the past 12 months (2024-2025), "
        "data breaches or privacy violations, critical vulnerabilities (CVEs), service outages due "
        "to security issues, and any major security-related news or reports. If no recent incidents "
        "are found, explicitly state 'No major security incidents found in the past year.' Provide "
        "specific dates and details whenever available."
    )

    user_prompt = (
        f"Domain: {domain}\n\n"
        f"SEARCH SPECIFICALLY for ALL security incidents and news involving {domain} from the ENTIRE period of the last {months} months (since {cutoff_date}). "
        f"IMPORTANT: Include items from the ENTIRE {months}-month period, not just recent ones. "
        f"While very recent incidents (last 6 months) are important, also include ALL relevant incidents and news from months 7-{months} of this period. "
        f"Search for credible posts or verified comments on any attack, data breach or security issue in the company's community websites. "
        f"Look for data breaches, supply chain attacks, or security compromises affecting {domain}.\n\n"
        f"Can you find any mentions of an outage from {domain} even on their community forum from december 2023)"
        # f"{supplemental_prompt}\n\n"
        "Return STRICT JSON with this exact shape (no extra fields):\n"
        "{\n"
        f"  \"domain\": \"{domain}\",\n"
        f"  \"since\": \"{cutoff_date}\",\n"
        "  \"summary\": \"<3-6 sentence executive summary>\",\n"
        "  \"incidents\": [\n"
        "    {\n"
        "      \"date\": \"YYYY-MM-DD\",\n"
        "      \"title\": \"...\",\n"
        "      \"description\": \"2-4 sentences (plain text, no markdown)\",\n"
        f"      \"relevance\": \"why this is relevant to {domain}\",\n"
        "      \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW\",\n"
        "      \"source\": \"https://... (REAL, WORKING URL or descriptive text if URL unavailable)\",\n"
        "      \"type\": \"incident\"\n"
        "    }\n"
        "  ],\n"
        "  \"news\": [\n"
        "    {\n"
        "      \"date\": \"YYYY-MM-DD\",\n"
        "      \"title\": \"...\",\n"
        "      \"description\": \"2-4 sentences (plain text, no markdown)\",\n"
        f"      \"relevance\": \"why this is relevant to {domain}\",\n"
        "      \"severity\": \"INFO\",\n"
        "      \"source\": \"https://... (REAL, WORKING URL or descriptive text if URL unavailable)\",\n"
        "      \"type\": \"news\"\n"
        "    }\n"
        "  ],\n"
        "  \"notes\": \"any caveats or monitoring recommendations\"\n"
        "}\n\n"
        f"Rules:\n"
        f"- CRITICAL: Include ALL items from the ENTIRE period since {cutoff_date} (last {months} months), not just the most recent ones.\n"
        f"- Do not exclude items just because they are older than 6 months - include everything from the full {months}-month period.\n"
        f"- DATE ACCURACY IS CRITICAL: The 'date' field must be the ACTUAL publication/incident date from the article, NOT today's date or the date you found it.\n"
        f"  * Look for phrases like 'reported on', 'occurred on', 'published', 'announced', 'discovered on', etc. in the article\n"
        f"  * Extract the date mentioned in that context and format as YYYY-MM-DD\n"
        f"  * If multiple dates are mentioned, use the date the incident occurred (not when it was reported later)\n"
        f"- For the source field: Only provide REAL, WORKING URLs. If you don't have an actual URL, describe where the information came from (e.g., 'Company community forum', 'Status page announcement', 'Company forum discussion', 'Security community reports', etc.). DO NOT CREATE FAKE URLs.\n"
        f"- Prefer primary sources.\n"
        f"- Sort by date descending in each category.\n"
        f"- Return ONLY JSON (no commentary)."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

def run_query_openai(domain: str, months: int, model: str, api_base: str, api_key: str, temperature: float = 0.1) -> str:
    """Direct OpenAI API implementation with Responses API web search"""
    start_time = time.time()

    # Use default OpenAI API base if not provided
    if not api_base:
        api_base = OPENAI_API_BASE

    # Ensure API key is set (use OPENAI_API_KEY)
    if not api_key:
        api_key = OPENAI_API_KEY
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")

    # Create OpenAI client with timeout to prevent hanging
    client = OpenAI(
        api_key=api_key, 
        base_url=api_base,
        timeout=120.0  # 2 minute timeout for HTTP requests (matches ThreadPoolExecutor timeout)
    )
    messages = build_messages(domain, months)

    # Prepare input text for logging
    input_text = ""
    for msg in messages:
        input_text += f"{msg['role']}: {msg['content']}\n"

    system_instruction = "\n\n".join(msg["content"] for msg in messages if msg["role"] == "system")
    full_prompt = "\n\n".join(
        f"{msg['role']}: {msg['content']}" for msg in messages if msg["role"] != "system"
    )

    try:
        request_params = {
            "model": model,
            "instructions": system_instruction,
            "input": full_prompt,
            "tools": [{"type": "web_search"}],
            "temperature": temperature,
            "max_output_tokens": 8000,
        }

        print(f"DEBUG [OpenAI]: Sending request with model: {request_params['model']}")
        print(f"DEBUG [OpenAI]: API base: {api_base}")
        print(f"DEBUG [OpenAI]: Using Responses API web_search tool")

        resp = client.responses.create(**request_params)
        output_text = extract_response_text(resp)

        # Log successful call to Supabase
        if SUPABASE_LOGGING_AVAILABLE:
            status = getattr(resp, "status", None)
            incomplete_details = getattr(resp, "incomplete_details", None)
            finish_reason = getattr(incomplete_details, "reason", None) or status

            log_llm_call(
                model=model,
                provider="openai",
                request_data={"input": full_prompt, "model": model, "temperature": temperature, "tools": [{"type": "web_search"}]},
                response_data={"finish_reason": finish_reason},
                context={"domain": domain, "months": months, "operation": "news_incidents_search"},
                service="news_incidents"
            )

        return output_text

    except Exception as e:
        # Log failed call to Supabase
        if SUPABASE_LOGGING_AVAILABLE:
            log_llm_call(
                model=model,
                provider="openai",
                request_data={"input": full_prompt, "model": model, "temperature": temperature, "tools": [{"type": "web_search"}]},
                error_message=str(e),
                context={"domain": domain, "months": months, "operation": "news_incidents_search"},
                service="news_incidents"
            )

        # Re-raise the exception
        raise


def run_query(domain: str, months: int, model: str, api_base: str, api_key: str, temperature: float = 0.1) -> str:
    """Run OpenAI Responses API with web_search (see run_query_openai)."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"[run_query] Using OpenAI Responses API for model: {model}")
    return run_query_openai(domain, months, model, api_base, api_key, temperature)


def _normalize_date(date_str: Optional[str]) -> str:
    if not date_str or not isinstance(date_str, str):
        return ""
    date_str = date_str.strip()
    # Try common formats
    fmts = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%d %b %Y",
        "%d %B %Y",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.date().isoformat()
        except Exception:
            continue
    # Fallback: if it looks like YYYY-MM, append -01
    if len(date_str) == 7 and date_str[4] in ("-", "/"):
        try:
            dt = datetime.strptime(date_str.replace("/", "-"), "%Y-%m")
            return dt.date().isoformat()
        except Exception:
            pass
    return date_str  # leave as-is


def _normalize_url(url: Optional[str]) -> str:
    if not isinstance(url, str):
        return "#"
    url = url.strip()
    if not url:
        return "#"
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "https://" + url




def query_incidents_json(domain: str, months: int = 36, model: str = None, api_base: str = None, api_key: str = None, temperature: float = 0.1, tier: Optional[str] = None) -> Dict:
    """
    Query security incidents and news for a domain using OpenAI (gpt-5.6-luna) with web search.

    Includes automatic deduplication against existing database records to prevent
    inserting duplicate news items from different sources.

    Args:
        domain: Company domain to investigate (e.g., 'example.com')
        months: Number of months to look back (default: 36)
        model: Explicit model name — if set, overrides the default OpenAI model
        api_base: API base URL (optional; defaults to OpenAI API)
        api_key: API key (optional; defaults to OPENAI_API_KEY)
        temperature: LLM temperature (default: 0.1)
        tier: Vendor tier (optional; retained for callers and logging — does not change the model)

    Returns:
        Dict containing incidents, news, summary, and metadata

    Model Selection:
        - Default: gpt-5.6-luna (OpenAI Responses API with web_search)
        - Explicit ``model`` argument overrides when provided
    """
    import logging
    logger = logging.getLogger(__name__)

    # Validate inputs
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string")

    if months < 1 or months > 120:
        raise ValueError("Months must be between 1 and 120")

    # Log API status
    logger.info(f"[Platform Integration] Processing domain: {domain}, tier: {tier}, months: {months}")
    logger.info(f"[API Status] Using Direct APIs")
    logger.info(f"[API Status] OPENAI_API_KEY: {'SET' if OPENAI_API_KEY else 'NOT SET'}")

    # Model selection: explicit `model` always wins (callers can still pass tier for context elsewhere)
    explicit_model = (str(model).strip() if model else "")
    if explicit_model:
        selected_model = explicit_model
        logger.info(f"[Model Override] Using provided model: {selected_model} (tier={tier!r} ignored for routing)")
    elif tier is not None and str(tier).strip():
        selected_model = get_model_for_tier(tier)
        logger.info(f"[Model selection] Tier: '{tier}' (informational) -> Model: {selected_model}")
    else:
        selected_model = OPENAI_DEFAULT_MODEL
        logger.info(f"[Default Fallback] Using default model: {selected_model}")

    # Validate selected model
    if not selected_model:
        raise ValueError("No model selected - check tier parameter and API availability")
    
    # Normalize model name - remove "models/" prefix if present (legacy support)
    if selected_model and selected_model.startswith("models/"):
        selected_model = selected_model.replace("models/", "")
    
    # Select API key and base URL (OpenAI only)
    if api_key is None:
        api_key = OPENAI_API_KEY
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")

    if api_base is None:
        api_base = OPENAI_API_BASE

    # Final validation
    if not api_key:
        raise ValueError(f"No API key available for model {selected_model}")

    provider = "OpenAI"
    key_preview = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else api_key
    logger.info(f"[Final Config] Provider: {provider}, Model: {selected_model}, API Key: {key_preview}, API Base: {api_base}")
    
    model = selected_model
    
    content = run_query(domain, months, model, api_base, api_key, temperature)
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Top-level JSON not an object")
    except Exception:
        # Try to extract JSON from markdown code blocks
        content_str = content.strip()
        if '```json' in content_str and '```' in content_str:
            try:
                # Extract JSON from markdown code block
                json_start = content_str.find('```json') + 7
                json_end = content_str.find('```', json_start)
                if json_end > json_start:
                    json_content = content_str[json_start:json_end].strip()
                    data = json.loads(json_content)
                    if isinstance(data, dict):
                        print(f"Successfully extracted JSON from markdown for domain: {domain}")
                        # Continue with normal processing
                    else:
                        raise ValueError("Extracted content is not a JSON object")
                else:
                    raise ValueError("Could not find closing markdown code block")
            except Exception as extract_error:
                print(f"Failed to extract JSON from markdown: {extract_error}")
                # Fallback to raw content
                return {
                    "domain": domain,
                    "since": (datetime.now(timezone.utc) - timedelta(days=months * 30)).date().isoformat(),
                    "summary": content.strip(),
                    "incidents": [],
                    "news": [],
                    "notes": "Model returned markdown-wrapped JSON that could not be parsed."
                }
        else:
        # Fallback when model did not return valid JSON
            return {
                "domain": domain,
                "since": (datetime.now(timezone.utc) - timedelta(days=months * 30)).date().isoformat(),
                "summary": content.strip(),
                "incidents": [],
                "news": [],
                "notes": "Model did not return valid JSON; raw content placed in summary."
            }

    # Ensure required keys
    data.setdefault("domain", domain)
    data.setdefault("since", (datetime.now(timezone.utc) - timedelta(days=months * 30)).date().isoformat())
    data.setdefault("incidents", [])
    data.setdefault("news", [])
    data.setdefault("summary", "")
    data.setdefault("notes", "")

    def normalize_items(items_list: List) -> List[Dict[str, str]]:
        """Normalize a list of incidents or news items"""
        normalized: List[Dict[str, str]] = []
        for item in items_list:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()
            description = str(item.get("description", "")).strip()
            # Trim overly long description to keep table readable
            if len(description) > 500:
                description = description[:497] + "..."
            severity = str(item.get("severity", "INFO")).upper().strip()
            if severity not in ALLOWED_SEVERITIES:
                severity = "INFO"
            source = _normalize_url(item.get("source"))
            date_norm = _normalize_date(item.get("date"))
            item_type = str(item.get("type", "")).strip()
            normalized.append({
                "date": date_norm,
                "title": title or "Untitled",
                "description": description,
                "severity": severity,
                "source": source,
                "relevance": str(item.get("relevance", "")).strip(),
                "type": item_type,
            })
        return normalized

    # Sort by date desc where possible
    def sort_key(x: Dict[str, str]):
        try:
            return datetime.strptime(x.get("date", ""), "%Y-%m-%d")
        except Exception:
            return datetime.min

    # Normalize both incidents and news
    normalized_incidents = normalize_items(data.get("incidents", []))
    
    # Check for known recent incidents that search might have missed
    
    normalized_incidents.sort(key=sort_key, reverse=True)
    data["incidents"] = normalized_incidents

    normalized_news = normalize_items(data.get("news", []))
    normalized_news.sort(key=sort_key, reverse=True)
    data["news"] = normalized_news

    # =========================================================================
    # DEDUPLICATION AGAINST EXISTING DATABASE RECORDS
    # =========================================================================
    # Before returning, deduplicate against existing records to prevent
    # inserting duplicate news items from different sources
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Dashboard'))
        from db_service import NewsService
        from deduplication import filter_out_duplicates, sanitize_news_items
        
        news_service = NewsService()
        
        # Get existing items for this domain
        existing_data = news_service.get_news_for_domain(domain, months=months)
        existing_incidents = existing_data.get('incidents', [])
        existing_news = existing_data.get('news', [])
        
        # Sanitize new items
        sanitized_incidents = sanitize_news_items(data["incidents"])
        sanitized_news = sanitize_news_items(data["news"])
        
        # Filter out duplicates
        filtered_incidents, dup_incident_indices = filter_out_duplicates(
            sanitized_incidents,
            existing_incidents
        )
        filtered_news, dup_news_indices = filter_out_duplicates(
            sanitized_news,
            existing_news
        )
        
        # Update data with filtered results
        original_incident_count = len(data["incidents"])
        original_news_count = len(data["news"])
        
        data["incidents"] = filtered_incidents
        data["news"] = filtered_news
        
        # Add deduplication summary to notes
        if dup_incident_indices or dup_news_indices:
            dedup_summary = (
                f"Deduplication applied: Removed {len(dup_incident_indices)} duplicate incident(s) "
                f"and {len(dup_news_indices)} duplicate news item(s) that already exist in database."
            )
            existing_notes = data.get("notes", "")
            data["notes"] = f"{dedup_summary}\n{existing_notes}".strip()
            
            logger.info(
                f"[Deduplication] Domain: {domain} - "
                f"Original: {original_incident_count} incidents, {original_news_count} news items | "
                f"After dedup: {len(filtered_incidents)} incidents, {len(filtered_news)} news items | "
                f"Removed: {len(dup_incident_indices)} incident duplicates, {len(dup_news_indices)} news duplicates"
            )
        
    except ImportError as e:
        logger.warning(f"Deduplication module not available: {e}")
        # Continue without deduplication if module not available
    except Exception as e:
        logger.warning(f"Error during deduplication: {e}", exc_info=True)
        # Continue with original data if deduplication fails
    
    return data


def format_console_output(data: Dict) -> str:
    """Format the data for nice console display with separate sections."""
    output = []
    
    # Header
    output.append("=" * 80)
    output.append(f"SECURITY ANALYSIS FOR: {data.get('domain', 'Unknown').upper()}")
    output.append("=" * 80)
    
    # Summary
    if data.get('summary'):
        output.append("\nEXECUTIVE SUMMARY")
        output.append("-" * 40)
        # Wrap long summary text
        summary = data['summary']
        words = summary.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + 1 <= 75:  # 75 chars per line
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(' '.join(current_line))
        
        for line in lines:
            output.append(f"  {line}")
    
    # Security Incidents Section
    incidents = data.get('incidents', [])
    output.append(f"\nSECURITY INCIDENTS ({len(incidents)} found)")
    output.append("-" * 40)
    
    if incidents:
        for i, incident in enumerate(incidents, 1):
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠', 
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(incident.get('severity', 'INFO'), '⚪')
            
            output.append(f"\n  {i}. {severity_emoji} {incident.get('severity', 'UNKNOWN')} - {incident.get('title', 'Untitled')}")
            output.append(f"     📅 Date: {incident.get('date', 'Unknown')}")
            
            # Wrap description
            desc = incident.get('description', 'No description available')
            desc_words = desc.split()
            desc_lines = []
            current_line = []
            current_length = 0
            
            for word in desc_words:
                if current_length + len(word) + 1 <= 70:
                    current_line.append(word)
                    current_length += len(word) + 1
                else:
                    if current_line:
                        desc_lines.append(' '.join(current_line))
                    current_line = [word]
                    current_length = len(word)
            
            if current_line:
                desc_lines.append(' '.join(current_line))
            
            for line in desc_lines:
                output.append(f"      {line}")
            
            if incident.get('source') and incident['source'] != '#':
                output.append(f"      Source: {incident['source']}")
    else:
        output.append("   No security incidents found in the specified timeframe.")
    
    # News Section
    news = data.get('news', [])
    output.append(f"\n COMPANY NEWS ({len(news)} found)")
    output.append("-" * 40)
    
    if news:
        for i, news_item in enumerate(news, 1):
            output.append(f"\n  {i}.  {news_item.get('title', 'Untitled')}")
            output.append(f"      Date: {news_item.get('date', 'Unknown')}")
            
            # Wrap description
            desc = news_item.get('description', 'No description available')
            desc_words = desc.split()
            desc_lines = []
            current_line = []
            current_length = 0
            
            for word in desc_words:
                if current_length + len(word) + 1 <= 70:
                    current_line.append(word)
                    current_length += len(word) + 1
                else:
                    if current_line:
                        desc_lines.append(' '.join(current_line))
                    current_line = [word]
                    current_length = len(word)
            
            if current_line:
                desc_lines.append(' '.join(current_line))
            
            for line in desc_lines:
                output.append(f"      {line}")
            
            if news_item.get('source') and news_item['source'] != '#':
                output.append(f"      Source: {news_item['source']}")
    else:
        output.append("    No relevant company news found in the specified timeframe.")
    
    # Notes
    if data.get('notes'):
        output.append(f"\n💡 NOTES")
        output.append("-" * 40)
        notes_words = data['notes'].split()
        notes_lines = []
        current_line = []
        current_length = 0
        
        for word in notes_words:
            if current_length + len(word) + 1 <= 75:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    notes_lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            notes_lines.append(' '.join(current_line))
        
        for line in notes_lines:
            output.append(f"  {line}")
    
    # Footer
    output.append(f"\n" + "=" * 80)
    output.append(f"Analysis Period: Since {data.get('since', 'Unknown')}")
    output.append("=" * 80)
    
    return '\n'.join(output)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Query recent security incidents and news for a domain using direct API calls"
    )
    # Make domain optional; prompt if not provided
    parser.add_argument("domain", nargs="?", default=None, help="Company domain to investigate, e.g., example.com")
    parser.add_argument("--months", type=int, default=36, help="Lookback window in months (default: 36)")
    parser.add_argument("--tier", type=str, default=None, help="Vendor tier (Tier 1, Tier 2, etc.) — logged only; model is always gpt-5.6-luna unless --model is set. If omitted, tier may be auto-fetched from the database.")
    # =============================================================================
    # MODEL SELECTION — OpenAI only (gpt-5.6-luna + web_search)
    # =============================================================================
    # Vendor tier does not route to a different provider or model.
    # Use --model to override OPENAI_DEFAULT_MODEL when needed.
    # =============================================================================
    parser.add_argument("--model", default=None, help=f"Override OpenAI model (default: {OPENAI_DEFAULT_MODEL})")
    parser.add_argument("--api-base", default=None, help="OpenAI API base URL (default: OPENAI_API_BASE)")
    parser.add_argument("--api-key", default=None, help="OpenAI API key (default: OPENAI_API_KEY)")
    parser.add_argument("--temperature", type=float, default=0.1, help="LLM temperature (default: 0.1)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output if response is JSON")
    parser.add_argument("--formatted", action="store_true", help="Display formatted console output with sections")

    args = parser.parse_args(argv)

    # Prompt for domain if none provided
    domain = args.domain
    if not domain:
        try:
            domain = input("Enter domain (e.g., example.com): ").strip()
        except EOFError:
            domain = ""
        if not domain:
            print("Error: Domain is required.", file=sys.stderr)
            return 1

    # Auto-fetch tier from database if not provided
    tier = args.tier
    if not tier and domain:
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Dashboard'))
            from db_service import VendorService
            
            vendor_service = VendorService()
            vendor = vendor_service.get_vendor_by_domain(domain)
            
            if vendor and vendor.get('tier'):
                tier = vendor['tier']
                print(f"[Auto-detected] Vendor tier for {domain}: {tier}")
            else:
                print(f"[Info] No tier found in database for {domain}, using default model")
        except Exception as e:
            print(f"[Warning] Could not fetch tier from database: {e}")
            print("[Info] Using default model selection")

    try:
        # Use normalized helper for CLI too when pretty-printing
        # Model selection is handled inside query_incidents_json based on tier
        data = query_incidents_json(
            domain=domain,
            months=args.months,
            model=args.model,  # Optional override; default is OPENAI_DEFAULT_MODEL
            api_base=args.api_base,
            api_key=args.api_key,
            temperature=args.temperature,
            tier=tier,  # Pass tier (either from args or auto-detected from database)
        )
    except Exception as e:
        print(f"Query failed: {e}", file=sys.stderr)
        return 1

    if args.pretty:
        # Pretty JSON output
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    elif args.formatted or (not args.pretty):
        # Default: Display nicely formatted console output
        print(format_console_output(data))
        return 0
    # Fallback: raw JSON
    print(json.dumps(data, ensure_ascii=False))
    return 0


def test_tier_selection():
    """
    Smoke-test get_model_for_tier: all tiers should map to OPENAI_DEFAULT_MODEL (gpt-5.6-luna).

    Returns:
        dict: Test results showing the selected model label for each sample tier value
    """
    import logging
    logger = logging.getLogger(__name__)

    results = {
        "direct_apis_configured": True,
        "openai_key_set": bool(OPENAI_API_KEY),
        "openai_api_base": OPENAI_API_BASE,
        "tier_tests": {}
    }

    test_tiers = ["Tier 1", "Tier 2", "Tier 3", "Unknown", None]

    for tier in test_tiers:
        try:
            model = get_model_for_tier(tier)
            results["tier_tests"][str(tier)] = {
                "selected_model": model,
                "matches_openai_default": model == OPENAI_DEFAULT_MODEL,
                "success": True,
            }
        except Exception as e:
            results["tier_tests"][str(tier)] = {
                "error": str(e),
                "success": False
            }

    logger.info(f"Tier selection test results: {results}")
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test-tier":
        print(json.dumps(test_tier_selection(), indent=2))
    else:
        sys.exit(main())
