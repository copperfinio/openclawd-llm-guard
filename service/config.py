"""LLM Guard configuration for Neubauer's 3-company setup"""
from llm_guard.input_scanners import (
    PromptInjection, Secrets, Code, InvisibleText,
    Toxicity, BanSubstrings, Regex
)
from llm_guard.output_scanners import (
    Sensitive, MaliciousURLs, NoRefusal, Regex as OutputRegex
)

# Business-specific API key patterns for Neubauer's companies
BUSINESS_API_PATTERNS = [
    r"lin_api_[A-Za-z0-9]{32,}",  # Linear API keys
    r"gcp_[A-Za-z0-9_-]{20,}",    # Google Cloud Platform keys
    r"ya29\.[A-Za-z0-9_-]{100,}", # OAuth2 access tokens
    r"GMAIL_APP_PASSWORD_\d=[a-z]{16}", # Gmail app passwords
    r"OAUTH_TOKEN_\d=[A-Za-z0-9.-]{50,}", # OAuth tokens
    r"GROQ_API_KEY=[a-zA-Z0-9_-]{50,}", # GROQ API key
]

# Company-sensitive terms (Owl, Voyidge, Fair Weather)
COMPANY_SENSITIVE_TERMS = [
    "hydra",           # Owl Technologies CRM
    "forum financial",
    "workstreet",
    "pooled trust",    # Voyidge
    "scott mury",
    "voyidge",
    "trackside.training", # Fair Weather Athletics
    "fair weather athletics",
    "gregory",         # Owl second-in-command
    "prabhu",         # Voyidge team member
]

def create_input_scanners():
    """Create input scanners for external content"""
    return [
        PromptInjection(threshold=0.8),
        Secrets(redact_mode=True),
        Code(languages=["Python", "JavaScript", "Go", "PowerShell"]),
        InvisibleText(),
        Toxicity(threshold=0.7),
        BanSubstrings(substrings=COMPANY_SENSITIVE_TERMS, redact=True),
        Regex(patterns=BUSINESS_API_PATTERNS, redact=True, is_blocked=True)
    ]

def create_output_scanners():
    """Create output scanners for AI responses"""
    return [
        Sensitive(entity_types=["EMAIL", "PHONE_NUMBER", "CREDIT_CARD"]),
        MaliciousURLs(),
        NoRefusal(),
        OutputRegex(patterns=BUSINESS_API_PATTERNS, redact=True, is_blocked=True)
    ]
