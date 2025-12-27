# body_analyzer.py - Advanced Email Body Analysis Engine
import re
import hashlib
import base64
import email
import urllib.parse
from datetime import datetime, timedelta
import json

class AdvancedBodyAnalyzer:
    """Advanced email body analysis with comprehensive threat detection"""
    
    def __init__(self):
        self.threat_patterns = {
            # Phishing indicators
            'urgency_patterns': [
                r'urgent', r'immediate', r'action required', r'account suspended',
                r'verify now', r'limited time', r'expire', r'deadline'
            ],
            'credential_harvesting': [
                r'enter your (?:password|credentials|login)', 
                r'confirm your (?:account|password)',
                r'security verification required',
                r'validate your account'
            ],
            'financial_indicators': [
                r'bank account', r'credit card', r'payment', r'billing',
                r'wire transfer', r'bitcoin', r'cryptocurrency'
            ],
            'suspicious_links': [
                r'http[s]?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w)*)?)?',
                r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'[a-zA-Z0-9.-]+\.(?:tk|ml|ga|cf|pw|xyz|top|click|download)'
            ],
            'attachment_indicators': [
                r'open the attached', r'download the file', r'click to download',
                r'invoice\.zip', r'document\.pdf', r'urgent\.exe'
            ],
            'social_engineering': [
                r'from your (?:it|hr|security) department',
                r'government agency', r'fbi', r'irs', r'bank security team',
                r'account verification team'
            ]
        }
        
        self.domain_reputation = {
            'high_risk_tlds': ['tk', 'ml', 'ga', 'cf', 'pw', 'xyz', 'top', 'click', 'download'],
            'suspicious_patterns': [
                r'[a-z0-9]{15,}',  # Very long domain names
                r'[a-z0-9]+\-[a-z0-9]+',  # Hyphenated domains
                r'[a-z0-9]+\d{3,}',  # Domains with many numbers
            ],
            'brand_spoofing': [
                r'(?:paypal|google|apple|microsoft|amazon|facebook)\-(?:secure|login|verify|account)',
                r'(?:bank|secure|verify)\-[a-z0-9]+\.com'
            ]
        }
        
        self.attachment_threats = {
            'executable_types': ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1'],
            'document_types': ['.pdf', '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'],
            'archive_types': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'macro_keywords': ['AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open']
        }
    
    def analyze_email_body(self, body_text, sender="", subject="", headers=None):
        """Comprehensive email body analysis"""
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'body_length': len(body_text) if body_text else 0,
            'threat_score': 0,
            'threat_level': 'LOW',
            'detections': [],
            'urls_found': [],
            'attachments_mentioned': [],
            'red_flags': [],
            'suspicious_domains': [],
            'recommendations': []
        }
        
        if not body_text:
            analysis_result['error'] = 'Empty email body'
            return analysis_result
        
        # Normalize text for analysis
        body_lower = body_text.lower()
        
        # 1. URL Analysis
        urls = self._extract_urls(body_text)
        analysis_result['urls_found'] = urls
        
        for url_info in urls:
            domain = url_info['domain']
            threat_level = self._analyze_domain_reputation(domain)
            
            if threat_level > 0.5:
                analysis_result['suspicious_domains'].append({
                    'domain': domain,
                    'threat_level': threat_level,
                    'url': url_info['full_url']
                })
                analysis_result['threat_score'] += 15
        
        # 2. Threat Pattern Detection
        for category, patterns in self.threat_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, body_lower)
                if found:
                    matches.extend(found)
            
            if matches:
                severity_weights = {
                    'urgency_patterns': 8,
                    'credential_harvesting': 20,
                    'financial_indicators': 12,
                    'suspicious_links': 15,
                    'attachment_indicators': 10,
                    'social_engineering': 18
                }
                
                weight = severity_weights.get(category, 5)
                analysis_result['threat_score'] += len(matches) * weight
                
                analysis_result['detections'].append({
                    'category': category,
                    'matches': matches,
                    'count': len(matches),
                    'severity': 'HIGH' if weight > 15 else 'MEDIUM'
                })
        
        # 3. Attachment Analysis
        attachments = self._analyze_mentioned_attachments(body_lower)
        analysis_result['attachments_mentioned'] = attachments
        
        for attachment in attachments:
            if attachment['extension'] in self.attachment_threats['executable_types']:
                analysis_result['threat_score'] += 25
                analysis_result['red_flags'].append(f"Executable attachment: {attachment['name']}")
            elif attachment['extension'] in self.attachment_threats['document_types']:
                analysis_result['threat_score'] += 15
                if any(keyword in body_lower for keyword in self.attachment_threats['macro_keywords']):
                    analysis_result['threat_score'] += 10
                    analysis_result['red_flags'].append(f"Macro-enabled document: {attachment['name']}")
        
        # 4. Social Engineering Detection
        social_indicators = self._detect_social_engineering(body_lower, sender, subject)
        analysis_result['detections'].extend(social_indicators['indicators'])
        analysis_result['threat_score'] += social_indicators['threat_score']
        
        # 5. Language Analysis
        language_risk = self._analyze_language_patterns(body_text)
        analysis_result['detections'].append(language_risk)
        analysis_result['threat_score'] += language_risk['threat_score']
        
        # 6. Final Risk Assessment
        if analysis_result['threat_score'] >= 60:
            analysis_result['threat_level'] = 'CRITICAL'
        elif analysis_result['threat_score'] >= 35:
            analysis_result['threat_level'] = 'HIGH'
        elif analysis_result['threat_score'] >= 15:
            analysis_result['threat_level'] = 'MEDIUM'
        else:
            analysis_result['threat_level'] = 'LOW'
        
        # 7. Generate Recommendations
        analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
        
        return analysis_result
    
    def _extract_urls(self, text):
        """Extract and analyze URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        url_info = []
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                url_info.append({
                    'full_url': url,
                    'domain': parsed.netloc.lower(),
                    'scheme': parsed.scheme,
                    'is_https': parsed.scheme == 'https'
                })
            except:
                continue
        
        return url_info
    
    def _analyze_domain_reputation(self, domain):
        """Analyze domain reputation and risk"""
        risk_score = 0
        
        # Check for suspicious TLDs
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in self.domain_reputation['high_risk_tlds']:
            risk_score += 0.3
        
        # Check for suspicious patterns
        for pattern in self.domain_reputation['suspicious_patterns']:
            if re.search(pattern, domain):
                risk_score += 0.4
        
        # Check for brand spoofing
        for pattern in self.domain_reputation['brand_spoofing']:
            if re.search(pattern, domain):
                risk_score += 0.6
        
        # Check domain length (very long domains are suspicious)
        if len(domain) > 50:
            risk_score += 0.2
        
        # Check for numbers in domain (often suspicious)
        if re.search(r'\d{3,}', domain):
            risk_score += 0.2
        
        return min(risk_score, 1.0)
    
    def _analyze_mentioned_attachments(self, text):
        """Analyze mentioned file attachments"""
        attachment_patterns = [
            r'(\w+\.(?:exe|scr|bat|cmd|vbs|js|jar|ps1|pdf|doc|docm|xls|xlsm|ppt|pptm|zip|rar|7z|tar|gz))',
            r'invoice[\w]*\.\w+',
            r'document[\w]*\.\w+',
            r'urgent[\w]*\.\w+'
        ]
        
        attachments = []
        for pattern in attachment_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]
                
                # Extract file extension
                extension = '.' + match.split('.')[-1].lower() if '.' in match else ''
                
                attachments.append({
                    'name': match,
                    'extension': extension,
                    'is_executable': extension in self.attachment_threats['executable_types'],
                    'is_document': extension in self.attachment_threats['document_types'],
                    'is_archive': extension in self.attachment_threats['archive_types']
                })
        
        return attachments
    
    def _detect_social_engineering(self, text, sender, subject):
        """Detect social engineering tactics"""
        indicators = []
        threat_score = 0
        
        # Authority impersonation
        authority_keywords = ['government', 'fbi', 'irs', 'bank security', 'it department', 'hr']
        authority_matches = [kw for kw in authority_keywords if kw in text]
        if authority_matches:
            indicators.append({
                'category': 'Authority Impersonation',
                'description': 'Pretending to be a trusted authority',
                'matches': authority_matches,
                'severity': 'HIGH'
            })
            threat_score += 15
        
        # Urgency creation
        urgency_matches = re.findall(r'(?:urgent|immediate|expires?|deadline|act now)', text)
        if len(urgency_matches) >= 3:
            indicators.append({
                'category': 'Artificial Urgency',
                'description': 'Creating false time pressure',
                'matches': urgency_matches,
                'severity': 'MEDIUM'
            })
            threat_score += 8
        
        # Fear-based tactics
        fear_keywords = ['suspended', 'locked', 'blocked', 'suspended', 'frozen']
        fear_matches = [kw for kw in fear_keywords if kw in text]
        if fear_matches:
            indicators.append({
                'category': 'Fear Tactics',
                'description': 'Using fear to trigger impulsive actions',
                'matches': fear_matches,
                'severity': 'HIGH'
            })
            threat_score += 12
        
        return {
            'indicators': indicators,
            'threat_score': threat_score
        }
    
    def _analyze_language_patterns(self, text):
        """Analyze language patterns for authenticity"""
        analysis = {
            'category': 'Language Analysis',
            'description': 'Analyzing writing style and authenticity',
            'threat_score': 0,
            'indicators': []
        }
        
        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'valued customer', 'sir/madam']
        if any(greeting in text.lower() for greeting in generic_greetings):
            analysis['indicators'].append('Generic greeting instead of personal address')
            analysis['threat_score'] += 5
        
        # Check for poor grammar/spelling (simplified)
        common_errors = ['recieve', 'definately', 'seperate', 'accomodate']
        errors_found = [error for error in common_errors if error in text.lower()]
        if len(errors_found) >= 2:
            analysis['indicators'].append(f'Potential spelling errors: {errors_found}')
            analysis['threat_score'] += 8
        
        # Check for excessive punctuation
        if re.search(r'[!?]{3,}', text):
            analysis['indicators'].append('Excessive punctuation (emotional manipulation)')
            analysis['threat_score'] += 6
        
        # Check for ALL CAPS usage
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        if caps_ratio > 0.3:
            analysis['indicators'].append('Excessive use of capital letters')
            analysis['threat_score'] += 4
        
        return analysis
    
    def _generate_recommendations(self, analysis_result):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if analysis_result['threat_level'] in ['HIGH', 'CRITICAL']:
            recommendations.append("🚨 DO NOT click any links or open attachments in this email")
            recommendations.append("📧 Report this email to your security team")
            recommendations.append("🔒 Verify sender identity through official channels")
        
        if analysis_result['suspicious_domains']:
            recommendations.append(f"🌐 Found {len(analysis_result['suspicious_domains'])} suspicious domains")
        
        if analysis_result['attachments_mentioned']:
            high_risk_attachments = [att for att in analysis_result['attachments_mentioned'] if att['is_executable']]
            if high_risk_attachments:
                recommendations.append("⚠️ High-risk executable attachments detected - DO NOT open")
        
        if analysis_result['threat_score'] > 30:
            recommendations.append("🛡️ Consider running this email through additional security tools")
        
        recommendations.append("✅ When in doubt, contact the sender through known, verified channels")
        
        return recommendations
    
    def get_detailed_explanation(self, analysis_result):
        """Generate detailed explanation of findings"""
        explanation = {
            'summary': f"Email analysis detected {analysis_result['threat_level']} risk level with score {analysis_result['threat_score']}/100",
            'findings': [],
            'technical_details': [],
            'recommendations': analysis_result['recommendations']
        }
        
        # Convert detections to human-readable explanations
        for detection in analysis_result['detections']:
            if detection['category'] == 'urgency_patterns':
                explanation['findings'].append(
                    f"Found {detection['count']} urgency indicators: {', '.join(detection['matches'][:3])}. "
                    "Attackers use urgency to bypass rational thinking and force quick decisions."
                )
            elif detection['category'] == 'credential_harvesting':
                explanation['findings'].append(
                    f"Detected {detection['count']} credential harvesting attempts. "
                    "Legitimate organizations never ask for passwords via email."
                )
            elif detection['category'] == 'social_engineering':
                explanation['findings'].append(
                    "Multiple social engineering tactics detected. This email may be attempting to manipulate emotions."
                )
        
        # Add technical details
        if analysis_result['urls_found']:
            explanation['technical_details'].append(
                f"URLs extracted: {len(analysis_result['urls_found'])}. "
                f"Suspicious domains: {len(analysis_result['suspicious_domains'])}"
            )
        
        if analysis_result['attachments_mentioned']:
            executable_count = sum(1 for att in analysis_result['attachments_mentioned'] if att['is_executable'])
            explanation['technical_details'].append(
                f"Attachments mentioned: {len(analysis_result['attachments_mentioned'])}. "
                f"Executable files: {executable_count}"
            )
        
        return explanation
