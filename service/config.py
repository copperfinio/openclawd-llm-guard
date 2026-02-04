"""LLM Guard configuration - customize for your organization"""
from llm_guard.input_scanners import (
    PromptInjection, Secrets, Code, InvisibleText,
    Toxicity, BanSubstrings, Regex
)
from llm_guard.output_scanners import (
    Sensitive, MaliciousURLs, NoRefusal, Regex as OutputRegex
)

# API key patterns to detect and redact
# Add patterns specific to your tools and services
BUSINESS_API_PATTERNS = [
    r"lin_api_[A-Za-z0-9]{32,}",  # Linear API keys
    r"gcp_[A-Za-z0-9_-]{20,}",    # Google Cloud Platform keys
    r"ya29\.[A-Za-z0-9_-]{100,}", # OAuth2 access tokens
    r"sk-[A-Za-z0-9]{48,}",       # OpenAI API keys
    r"xoxb-[A-Za-z0-9-]+",        # Slack bot tokens
    r"ghp_[A-Za-z0-9]{36,}",      # GitHub personal access tokens
    # Add your own patterns below:
    # r"YOUR_SERVICE_[A-Za-z0-9]+",
]

# Sensitive terms specific to your organization
# These will be flagged and optionally redacted
COMPANY_SENSITIVE_TERMS = [
    # Add your sensitive terms here, for example:
    # "project-codename",
    # "internal-tool-name",
    # "client-name",
    # "partner-company",
]

def create_input_scanners():
    """Create input scanners for external content"""
    scanners = [
        PromptInjection(threshold=0.8),
        Secrets(redact_mode=True),
        Code(languages=["Python", "JavaScript", "Go", "PowerShell"]),
        InvisibleText(),
        Toxicity(threshold=0.7),
        Regex(patterns=BUSINESS_API_PATTERNS, redact=True, is_blocked=True)
    ]

    # Only add BanSubstrings if terms are configured
    if COMPANY_SENSITIVE_TERMS:
        scanners.append(BanSubstrings(substrings=COMPANY_SENSITIVE_TERMS, redact=True))

    return scanners

def create_output_scanners():
    """Create output scanners for AI responses"""
    return [
        Sensitive(entity_types=["EMAIL", "PHONE_NUMBER", "CREDIT_CARD"]),
        MaliciousURLs(),
        NoRefusal(),
        OutputRegex(patterns=BUSINESS_API_PATTERNS, redact=True, is_blocked=True)
    ]
