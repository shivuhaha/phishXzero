# phishing_psychology.py - Educational content about phishing psychology and social engineering

PHISHING_PSYCHOLOGY_DATA = {
    "attack_types": [
        {
            "name": "Email Phishing",
            "description": "Most common form of phishing attack",
            "prevalence": "65%",
            "psychology": "Uses urgency, authority, and social proof",
            "examples": ["Account verification", "Urgent action required", "System update"],
            "color": "#ef4444"
        },
        {
            "name": "Spear Phishing",
            "description": "Highly targeted attacks with personalized information",
            "prevalence": "15%",
            "psychology": "Exploits trust through personalization",
            "examples": ["CEO fraud", "Payroll phishing", "Targeted department emails"],
            "color": "#f97316"
        },
        {
            "name": "Whaling",
            "description": "Attacks targeting senior executives and high-value targets",
            "prevalence": "8%",
            "psychology": "Uses authority and business context",
            "examples": ["Board member emails", "Wire transfer requests", "Confidential data"],
            "color": "#d946ef"
        },
        {
            "name": "Smishing",
            "description": "Phishing attacks via SMS text messages",
            "prevalence": "7%",
            "psychology": "Immediate action triggers, mobile trust",
            "examples": ["Bank alerts", "Package delivery", "Account lockouts"],
            "color": "#0ea5e9"
        },
        {
            "name": "Vishing",
            "description": "Voice-based phishing using phone calls or VoIP",
            "prevalence": "5%",
            "psychology": "Voice authority, social engineering",
            "examples": ["Tech support calls", "IRS impersonation", "Bank fraud"],
            "color": "#06b6d4"
        }
    ],
    
    "social_engineering_tactics": [
        {
            "name": "Urgency",
            "description": "Creating time pressure to bypass decision-making",
            "risk_level": "CRITICAL",
            "keywords": ["urgent", "immediately", "act now", "expires", "limited time", "deadline"],
            "mitigations": ["Verify through official channels before taking action", "Take time to think", "Don't act on pressure"]
        },
        {
            "name": "Authority",
            "description": "Impersonating trusted authority figures or institutions",
            "risk_level": "CRITICAL",
            "keywords": ["CEO", "HR", "IT Department", "IRS", "FBI", "Bank", "Government"],
            "mitigations": ["Call back using official phone numbers from official website", "Verify identity independently", "Ask for ID or credentials"]
        },
        {
            "name": "Social Proof",
            "description": "Leveraging peer behavior or consensus",
            "risk_level": "HIGH",
            "keywords": ["everyone has updated", "most users", "trending", "popular", "verified"],
            "mitigations": ["Verify claims independently", "Don't trust crowd mentality", "Check official sources"]
        },
        {
            "name": "Reciprocity",
            "description": "Creating obligation through initial offers or help",
            "risk_level": "HIGH",
            "keywords": ["free offer", "prize", "reward", "gift", "bonus", "exclusive"],
            "mitigations": ["Be suspicious of unsolicited offers", "Research before engaging", "Verify legitimacy"]
        },
        {
            "name": "Scarcity",
            "description": "Creating fear of missing out or resource depletion",
            "risk_level": "HIGH",
            "keywords": ["limited slots", "only 5 left", "exclusive", "rare", "stock running out"],
            "mitigations": ["Take time to verify before clicking", "Don't panic", "Check real sources"]
        },
        {
            "name": "Authority Bias",
            "description": "Tendency to comply with authority figures",
            "risk_level": "CRITICAL",
            "keywords": ["must comply", "company policy", "mandatory", "required", "official"],
            "mitigations": ["Verify identity before following instructions", "Ask for written confirmation", "Use official channels"]
        },
        {
            "name": "Fear",
            "description": "Exploiting fear of consequences or threats",
            "risk_level": "CRITICAL",
            "keywords": ["account suspended", "action required", "verify now", "unauthorized access", "compromised"],
            "mitigations": ["Contact organization directly through official channels", "Don't panic click", "Verify alerts"]
        },
        {
            "name": "Curiosity",
            "description": "Exploiting natural curiosity about leaked or scandal information",
            "risk_level": "MEDIUM",
            "keywords": ["leaked", "scandal", "shocking", "you won't believe", "see what"],
            "mitigations": ["Avoid clicking suspicious links", "Be skeptical of dramatic claims", "Verify sources"]
        }
    ],
    
    "phishing_indicators": {
        "Email Headers": {
            "red_flags": [
                "Sender domain doesn't match company",
                "Missing SPF/DKIM/DMARC records",
                "Generic greeting instead of name",
                "Unusual sender email address"
            ],
            "severity": "HIGH"
        },
        "Content": {
            "red_flags": [
                "Spelling and grammar errors",
                "Requests for credentials or sensitive info",
                "Urgent action required language",
                "Unusual requests from known contacts",
                "Mismatched URLs in links"
            ],
            "severity": "CRITICAL"
        },
        "URLs": {
            "red_flags": [
                "IP-based URLs instead of domain names",
                "URL shorteners hiding destination",
                "Misspelled domain names (typosquatting)",
                "HTTPS with invalid certificates",
                "Multiple redirects"
            ],
            "severity": "CRITICAL"
        },
        "Attachments": {
            "red_flags": [
                "Executable files (.exe, .bat, .cmd)",
                "Macro-enabled Office documents",
                "Unexpected file types",
                "Large file sizes",
                "Recently modified files"
            ],
            "severity": "CRITICAL"
        },
        "Context": {
            "red_flags": [
                "Unsolicited email",
                "Unusual time of delivery",
                "Mismatch with normal communication patterns",
                "Missing previous correspondence",
                "External email marked as internal"
            ],
            "severity": "MEDIUM"
        }
    },
    
    "victim_psychology": [
        {
            "name": "Confirmation Bias",
            "description": "Tendency to seek information confirming pre-existing beliefs",
            "exploitation": "Attackers craft messages matching victim expectations",
            "defense": "Question assumptions and seek contradicting evidence"
        },
        {
            "name": "Authority Bias",
            "description": "Tendency to attribute greater accuracy to authority figures",
            "exploitation": "Impersonating bosses, IT staff, or institutions",
            "defense": "Verify authority through independent means"
        },
        {
            "name": "Trust Bias",
            "description": "Tendency to trust familiar senders or formats",
            "exploitation": "Spoofing trusted sender addresses or mimicking known templates",
            "defense": "Verify unexpected requests from known contacts"
        },
        {
            "name": "Urgency Bias",
            "description": "Tendency to make quick decisions under time pressure",
            "exploitation": "Creating artificial deadlines",
            "defense": "Take time to verify before acting"
        }
    ],
    
    "statistics": {
        "emails_per_day": "3.4B",
        "success_rate": "3.4%",
        "avg_cost_per_breach": "$4.65M",
        "avg_detection_time": "177 days",
        "global_impact": {
            "phishing_emails_daily": "3.4 billion",
            "success_rate": "3.4%",
            "average_cost_per_breach": "$4.65 million",
            "time_to_detect": "177 days"
        },
        "industry_breakdown": {
            "Manufacturing": {"attacks_per_month": 248, "avg_loss": 6.35},
            "Financial": {"attacks_per_month": 312, "avg_loss": 5.86},
            "Healthcare": {"attacks_per_month": 287, "avg_loss": 10.93},
            "Education": {"attacks_per_month": 156, "avg_loss": 3.86},
            "Technology": {"attacks_per_month": 203, "avg_loss": 4.59}
        },
        "success_factors": {
            "click_rate": "12%",
            "attachment_open": "8%",
            "credential_compromise": "3%",
            "data_breach": "1%"
        }
    },
    
    "best_practices": [
        {
            "name": "Verify Sender Identity",
            "description": "Always verify the sender's identity through official channels",
            "priority": "CRITICAL"
        },
        {
            "name": "Check URLs Before Clicking",
            "description": "Hover over links to see actual destination, verify domain matches sender",
            "priority": "CRITICAL"
        },
        {
            "name": "Look for Red Flags",
            "description": "Check for spelling errors, generic greetings, urgency, and suspicious requests",
            "priority": "CRITICAL"
        },
        {
            "name": "Enable Multi-Factor Authentication",
            "description": "MFA significantly reduces account compromise even if credentials leaked",
            "priority": "CRITICAL"
        },
        {
            "name": "Keep Software Updated",
            "description": "Regular updates patch security vulnerabilities exploited by attackers",
            "priority": "HIGH"
        },
        {
            "name": "Report Suspicious Emails",
            "description": "Report phishing attempts to IT/Security team for awareness",
            "priority": "HIGH"
        },
        {
            "name": "Training and Awareness",
            "description": "Regular security training increases detection rates by 20-30%",
            "priority": "HIGH"
        },
        {
            "name": "Use Email Authentication",
            "description": "SPF, DKIM, DMARC help verify legitimate sender domains",
            "priority": "MEDIUM"
        }
    ]
}
