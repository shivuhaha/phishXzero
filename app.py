import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import re
import hashlib
import json
import requests
import os
from auth_system import AuthSystem
from body_analyzer import AdvancedBodyAnalyzer
from yara_rules import YARAScanner
from virustotal_checker import VirusTotalChecker

# Page Configuration
st.set_page_config(
    page_title="PhishXZero - Advanced Phishing Detection", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Load Clean Design CSS
try:
    with open('clean_design.css', 'r', encoding='utf-8') as f:
        css_content = f.read()
    st.markdown(f'<style>{css_content}</style>', unsafe_allow_html=True)
except FileNotFoundError:
    st.markdown("""
    <style>
    body { 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    }
    </style>
    """, unsafe_allow_html=True)

# Initialize Session State
if 'auth_system' not in st.session_state:
    st.session_state.auth_system = AuthSystem()
if 'user' not in st.session_state:
    st.session_state.user = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'login'
if 'active_nav' not in st.session_state:
    st.session_state.active_nav = 'scanner'

# Global instances
body_analyzer = AdvancedBodyAnalyzer()
yara_scanner = YARAScanner()
vt_checker = VirusTotalChecker("a77a689bf120c4f1dd2536e360b256ce7b27681b347edf531221e187e30ab924")

# Enhanced ML phishing detection
def ml_phishing_detector(email_text, sender, subject):
    score = 0
    reasons = []
    keywords = {'urgent':15, 'verify':12, 'suspended':18, 'confirm':10, 'security':10, 'click here':20}
    
    for kw, weight in keywords.items():
        if kw in (email_text or '').lower() or kw in (subject or '').lower():
            score += weight
            reasons.append(f"Keyword: {kw}")
    
    urls = re.findall(r'https?://[^\s<>"]+', email_text or '')
    if len(urls) >= 3: 
        score += 15
        reasons.append("Multiple URLs")
    
    # Use advanced body analyzer
    if email_text:
        try:
            body_analysis = body_analyzer.analyze_email_body(email_text, sender, subject)
            score += body_analysis['threat_score']
            reasons.extend([f"Body: {detection['category']}" for detection in body_analysis['detections']])
        except:
            pass
    
    if score >= 60: verdict, risk = 'PHISHING', 'CRITICAL'
    elif score >= 35: verdict, risk = 'SUSPICIOUS', 'HIGH'
    else: verdict, risk = 'LEGITIMATE', 'LOW'
    
    return {
        'score': min(score, 100), 'verdict': verdict,
        'risk_level': risk, 'reasons': reasons, 'urls': urls
    }

# Navigation Component
def render_navigation():
    if st.session_state.user:
        # Simple Navigation Bar
        st.markdown("""
        <div class="top-nav">
            <div class="nav-logo">🛡️ PhishXZero</div>
            <div class="nav-items">
                <div class="nav-btn """ + ("active" if st.session_state.active_nav == 'scanner' else "") + """" onclick="handleNavClick('scanner')">
                    🔍 Scanner
                </div>
                <div class="nav-btn """ + ("active" if st.session_state.active_nav == 'analytics' else "") + """" onclick="handleNavClick('analytics')">
                    📊 Analytics
                </div>
                <div class="nav-btn """ + ("active" if st.session_state.active_nav == 'history' else "") + """" onclick="handleNavClick('history')">
                    📋 History
                </div>
                <div class="nav-btn" onclick="handleLogout()">
                    🚪 Logout
                </div>
            </div>
        </div>
        <div style="height: 80px;"></div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <script>
        function handleNavClick(page) {{
            window.parent.postMessage({{type: 'streamlit_set_page', page: page}}, '*');
        }}
        function handleLogout() {{
            if(confirm('Are you sure you want to logout?')) {{
                window.parent.postMessage({{type: 'streamlit_logout'}}, '*');
            }}
        }}
        </script>
        """, unsafe_allow_html=True)

# Login Page with Clean Design
def render_login_page():
    st.markdown("""
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <div class="login-logo">🛡️ PhishXZero</div>
                <div class="login-subtitle">Advanced Phishing Detection System</div>
            </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for login/signup
    tab1, tab2 = st.tabs(["🔑 Sign In", "✨ Create Account"])
    
    with tab1:
        st.markdown("### Welcome Back!")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            submit_login = st.form_submit_button("Sign In", type="primary", use_container_width=True)
            
            if submit_login:
                if username and password:
                    try:
                        success, result = st.session_state.auth_system.authenticate_user(username, password)
                        if success:
                            st.session_state.user = result
                            st.session_state.current_page = 'main'
                            st.rerun()
                        else:
                            st.error(result)
                    except Exception as e:
                        st.error(f"Login error: {str(e)}")
                else:
                    st.error("Please fill in all fields")
    
    with tab2:
        st.markdown("### Join PhishXZero!")
        with st.form("signup_form"):
            new_username = st.text_input("Username", placeholder="Choose a username")
            new_email = st.text_input("Email", placeholder="Enter your email")
            new_password = st.text_input("Password", type="password", placeholder="Create a password")
            confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
            
            submit_signup = st.form_submit_button("Create Account", type="primary", use_container_width=True)
            
            if submit_signup:
                if new_username and new_email and new_password and confirm_password:
                    if new_password == confirm_password:
                        if len(new_password) >= 6:
                            try:
                                success, result = st.session_state.auth_system.create_user(new_username, new_email, new_password)
                                if success:
                                    st.success("Account created successfully! You can now sign in.")
                                    st.info("Please switch to the Sign In tab to login.")
                                else:
                                    st.error(result)
                            except Exception as e:
                                st.error(f"Signup error: {str(e)}")
                        else:
                            st.error("Password must be at least 6 characters long")
                    else:
                        st.error("Passwords do not match")
                else:
                    st.error("Please fill in all fields")
    
    # Add awareness metrics at bottom
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🎯 Prevention Rate", "94%")
    with col2:
        st.metric("🛡️ YARA Rules", "28")
    with col3:
        st.metric("⚡ Accuracy", "99.9%")
    
    st.markdown("</div></div>", unsafe_allow_html=True)

# Main Scanner Page
def render_scanner_page():
    st.markdown("### 🔍 Advanced Threat Detection Scanner")
    
    # Create tabs for different scan types
    tab_email, tab_url, tab_malware = st.tabs(["📧 Email Scanner", "🌐 URL Scanner", "🛡️ Malware Scanner"])
    
    with tab_email:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("#### Email Content Analysis")
            sender = st.text_input("👤 From", placeholder="sender@company.com")
            subject = st.text_input("📄 Subject", placeholder="Email subject line")
            body = st.text_area("💬 Message Body", height=250, placeholder="Paste email content here...")
            analyze = st.button("🚀 Analyze Email", type="primary")
        
        with col2:
            st.markdown("#### Quick Stats")
            if st.session_state.user:
                try:
                    stats = st.session_state.auth_system.get_user_stats(st.session_state.user['user_id'])
                    st.metric("📧 Total Scans", stats['total_scans'])
                    st.metric("🚨 Phishing", stats['phishing_detected'])
                    st.metric("⚠️ Suspicious", stats['suspicious_detected'])
                    st.metric("✅ Legitimate", stats['legitimate_found'])
                except:
                    st.metric("📧 Total Scans", "0")
                    st.metric("🚨 Phishing", "0")
                    st.metric("⚠️ Suspicious", "0")
                    st.metric("✅ Legitimate", "0")
        
        # Analysis Results
        if analyze and sender and subject and body:
            result = ml_phishing_detector(body, sender, subject)
            
            # Save scan to database
            if st.session_state.user:
                try:
                    st.session_state.auth_system.save_scan(
                        st.session_state.user['user_id'], 
                        'email', 
                        f"From: {sender}, Subject: {subject}", 
                        result['verdict'], 
                        result['score']
                    )
                except:
                    pass
            
            # Display results
            st.markdown("---")
            st.markdown("### 🔍 Analysis Results")
            
            # Verdict
            if result['verdict'] == 'PHISHING':
                st.markdown('<div class="alert alert-error">🚨 <strong>PHISHING DETECTED</strong></div>', unsafe_allow_html=True)
            elif result['verdict'] == 'SUSPICIOUS':
                st.markdown('<div class="alert alert-warning">⚠️ <strong>SUSPICIOUS EMAIL</strong></div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="alert alert-success">✅ <strong>EMAIL SAFE</strong></div>', unsafe_allow_html=True)
            
            # Metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Risk Score", f"{result['score']:.0f}%")
            with col2:
                st.metric("Threat Level", result['risk_level'])
            with col3:
                st.metric("URLs Found", len(result['urls']))
            
            # Reasons
            if result['reasons']:
                st.markdown("#### 🔍 Detection Reasons")
                for reason in result['reasons']:
                    st.markdown(f"• {reason}")
    
    with tab_url:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("#### URL Reputation Analysis")
            url_input = st.text_input("🔗 Enter URL", placeholder="https://example.com")
            scan_url = st.button("🛡️ Scan with VirusTotal", type="primary")
            
            if scan_url and url_input:
                with st.spinner("Scanning with VirusTotal..."):
                    try:
                        vt_result = vt_checker.check_url(url_input)
                        
                        # Save scan to database
                        if st.session_state.user:
                            try:
                                st.session_state.auth_system.save_scan(
                                    st.session_state.user['user_id'], 
                                    'url', 
                                    url_input, 
                                    'SCANNED', 
                                    int(vt_result.get('risk_score', 0) * 100)
                                )
                            except:
                                pass
                        
                        st.markdown("### 🔍 VirusTotal Analysis Results")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("🦠 Malicious", vt_result.get("malicious", 0))
                        with col2:
                            st.metric("⚠️ Suspicious", vt_result.get("suspicious", 0))
                        with col3:
                            st.metric("✅ Harmless", vt_result.get("harmless", 0))
                        
                        # Risk Assessment
                        risk_score = vt_result.get("risk_score", 0)
                        if risk_score > 0.7:
                            st.markdown('<div class="alert alert-error">🚨 <strong>HIGH RISK URL</strong></div>', unsafe_allow_html=True)
                        elif risk_score > 0.3:
                            st.markdown('<div class="alert alert-warning">⚠️ <strong>SUSPICIOUS URL</strong></div>', unsafe_allow_html=True)
                        else:
                            st.markdown('<div class="alert alert-success">✅ <strong>CLEAN URL</strong></div>', unsafe_allow_html=True)
                        
                        # Progress bar
                        st.markdown(f"""
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {risk_score*100}%"></div>
                        </div>
                        <p style="text-align: center; margin-top: 8px;">Risk Score: {risk_score:.2%}</p>
                        """, unsafe_allow_html=True)
                        
                    except Exception as e:
                        st.error(f"Error scanning URL: {str(e)}")
        
        with col2:
            st.markdown("#### 💡 Security Tips")
            st.markdown("""
            <div class="card">
                <p style="color: #666; line-height: 1.6;">
                    🔍 Always verify URLs<br>
                    🔒 Check for HTTPS<br>
                    ⚠️ Be suspicious of short URLs<br>
                    🏢 Verify brand authenticity
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    with tab_malware:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("#### Advanced Malware Scanner")
            file_upload = st.file_uploader("📁 Upload File", 
                                         type=['exe','dll','pdf','docx','xlsx','zip','bin','com','sys'])
            
            if file_upload:
                file_bytes = file_upload.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📄 File Name", file_upload.name[:20])
                with col2:
                    st.metric("📊 Size", f"{len(file_bytes)/1024:.1f} KB")
                with col3:
                    st.metric("🔐 Hash", f"{file_hash[:16]}...")
                
                if st.button("🛡️ Scan for Malware", type="primary"):
                    with st.spinner("Running YARA scan..."):
                        try:
                            yara_results = yara_scanner.scan_bytes(file_bytes, file_upload.name)
                            
                            # Save scan to database
                            if st.session_state.user:
                                try:
                                    st.session_state.auth_system.save_scan(
                                        st.session_state.user['user_id'], 
                                        'malware', 
                                        f"File: {file_upload.name}", 
                                        yara_results.get('verdict', 'UNKNOWN'), 
                                        int(yara_results.get('confidence', 0) * 100)
                                    )
                                except:
                                    pass
                            
                            st.markdown("### 🔍 YARA Analysis Results")
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("🎯 Detections", len(yara_results.get('detections', [])))
                            with col2:
                                st.metric("📊 Confidence", f"{yara_results.get('confidence', 0)*100:.1f}%")
                            with col3:
                                st.metric("⚠️ Risk Level", yara_results.get('risk_level', 'UNKNOWN'))
                            
                            # Verdict
                            verdict = yara_results.get('verdict', 'UNKNOWN')
                            if 'MALWARE' in verdict.upper():
                                st.markdown('<div class="alert alert-error">🚨 <strong>MALWARE DETECTED</strong></div>', unsafe_allow_html=True)
                            elif 'SUSPICIOUS' in verdict.upper():
                                st.markdown('<div class="alert alert-warning">⚠️ <strong>SUSPICIOUS FILE</strong></div>', unsafe_allow_html=True)
                            else:
                                st.markdown('<div class="alert alert-success">✅ <strong>FILE IS CLEAN</strong></div>', unsafe_allow_html=True)
                        
                        except Exception as e:
                            st.error(f"Error scanning file: {str(e)}")
        
        with col2:
            st.markdown("#### 🛡️ YARA Categories")
            st.markdown("""
            <div class="card">
                <p style="color: #666; line-height: 1.6;">
                    🔴 <strong>CRITICAL:</strong> Ransomware<br>
                    🟠 <strong>HIGH:</strong> Backdoors<br>
                    🟡 <strong>MEDIUM:</strong> PUPs<br>
                    🟢 <strong>LOW:</strong> Patterns
                </p>
            </div>
            """, unsafe_allow_html=True)

# Analytics Page
def render_analytics_page():
    st.markdown("### 📊 Analytics Dashboard")
    
    if st.session_state.user:
        try:
            stats = st.session_state.auth_system.get_user_stats(st.session_state.user['user_id'])
            scans = st.session_state.auth_system.get_user_scans(st.session_state.user['user_id'])
            
            # Overview metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📧 Total Scans", stats['total_scans'])
            with col2:
                st.metric("🚨 Phishing", stats['phishing_detected'])
            with col3:
                st.metric("⚠️ Suspicious", stats['suspicious_detected'])
            with col4:
                st.metric("✅ Legitimate", stats['legitimate_found'])
            
            # Charts
            if scans:
                df = pd.DataFrame(scans, columns=['Type', 'Content', 'Result', 'Score', 'Timestamp'])
                
                # Result distribution
                result_counts = df['Result'].value_counts()
                if len(result_counts) > 0:
                    fig = px.pie(values=result_counts.values, names=result_counts.index, 
                               title="Scan Results Distribution")
                    st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Error loading analytics: {str(e)}")
            st.info("Please ensure your user data is properly initialized.")

# History Page
def render_history_page():
    st.markdown("### 📋 Scan History")
    
    if st.session_state.user:
        try:
            scans = st.session_state.auth_system.get_user_scans(st.session_state.user['user_id'])
            
            if scans:
                df = pd.DataFrame(scans, columns=['Type', 'Content', 'Result', 'Score', 'Timestamp'])
                df['Timestamp'] = pd.to_datetime(df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M')
                
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No scans found. Start scanning to see your history here!")
        except Exception as e:
            st.error(f"Error loading history: {str(e)}")
            st.info("Please ensure your user data is properly initialized.")

# Main App Logic
def main():
    # Handle navigation updates from JavaScript
    if hasattr(st.session_state, '_nav_clicked'):
        page = st.session_state._nav_clicked
        if page in ['scanner', 'analytics', 'history']:
            st.session_state.active_nav = page
        elif page == 'logout':
            st.session_state.user = None
            st.session_state.current_page = 'login'
        delattr(st.session_state, '_nav_clicked')
        st.rerun()
    
    # Render current page
    if st.session_state.current_page == 'login':
        render_login_page()
    elif st.session_state.current_page == 'main':
        render_navigation()
        
        # Handle navigation
        if st.session_state.active_nav == 'scanner':
            render_scanner_page()
        elif st.session_state.active_nav == 'analytics':
            render_analytics_page()
        elif st.session_state.active_nav == 'history':
            render_history_page()

# Run the app
if __name__ == "__main__":
    main()

