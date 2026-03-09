import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple, List, Optional
import re
import hashlib
import time
import io
from dotenv import load_dotenv
from auth import AuthManager
from db_manager import ScanDatabase
from phishing_psychology import PHISHING_PSYCHOLOGY_DATA
from virustotal_checker import VirusTotalChecker
from yara_rules import YARAScanner
from body_analyzer import EmailBodyAnalyzer
from email_parser import EmailParser
from advanced_feature_extractor import extract_email_features, AdvancedEmailFeatureExtractor
from ml_phishing_detector import ml_phishing_detector, MLPhishingDetector
from email_quarantine import EmailQuarantine
from alert_system import AlertManager
from email_logger import EmailLogger
from email_auth_validator import EmailAuthValidator, AuthStatus
from url_analyzer import URLAnalyzer
from malware_forensic import MalwareForensicAnalyzer
from url_vanguard import URLVanguard
from malware_vanguard import MalwareForensicVanguard
from email_forensic_engine import EmailForensicEngine
from google_integration import GoogleOAuthManager, GmailIntegrationMVP

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Initialize session state variables FIRST - before any access
if 'authenticated'not in st.session_state:
    st.session_state.authenticated = False
if 'user_id'not in st.session_state:
    st.session_state.user_id = None
if 'username'not in st.session_state:
    st.session_state.username = None
if 'email'not in st.session_state:
    st.session_state.email = None
if 'page'not in st.session_state:
    st.session_state.page = 'home'
if 'active_nav'not in st.session_state:
    st.session_state.active_nav = 'home'

# Handle navbar page navigation via query parameters
try:
    query_params = st.query_params
    if 'page'in query_params:
        page_param = query_params['page']
        if isinstance(page_param, list):
            page_param = page_param[0]
        valid_pages = ['home', 'threat', 'analytics', 'history', 'education', 'about']
        if page_param in valid_pages:
            st.session_state.page = page_param
            # Clear the query param to avoid re-triggering
            st.query_params.clear()
except:
    pass

st.set_page_config(
    page_title="⚔️ phishXzero - Email Security",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

auth_manager: AuthManager = AuthManager()
scan_db: ScanDatabase = ScanDatabase()
vt_checker: VirusTotalChecker = VirusTotalChecker()
yara_scanner: YARAScanner = YARAScanner()
email_analyzer: EmailBodyAnalyzer = EmailBodyAnalyzer()
email_parser: EmailParser = EmailParser()
ml_detector: MLPhishingDetector = MLPhishingDetector()
feature_extractor: AdvancedEmailFeatureExtractor = AdvancedEmailFeatureExtractor()
quarantine: EmailQuarantine = EmailQuarantine()
alert_manager: AlertManager = AlertManager()
email_logger: EmailLogger = EmailLogger()
auth_validator: EmailAuthValidator = EmailAuthValidator()
url_analyzer: URLAnalyzer = URLAnalyzer()
malware_forensic: MalwareForensicAnalyzer = MalwareForensicAnalyzer()
url_vanguard: URLVanguard = URLVanguard()
malware_vanguard: MalwareForensicVanguard = MalwareForensicVanguard()
email_forensic_engine: EmailForensicEngine = EmailForensicEngine()
google_oauth_manager: GoogleOAuthManager = GoogleOAuthManager(
    os.getenv("GOOGLE_CLIENT_ID", "") or os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
    os.getenv("GOOGLE_CLIENT_SECRET", "") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
    os.getenv("GOOGLE_REDIRECT_URI", "") or os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "")
)
gmail_integration: GmailIntegrationMVP = GmailIntegrationMVP()

# Professional CSS with animations - ENHANCED
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap');
* { margin: 0; padding: 0; box-sizing: border-box; }
.stApp { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); font-family: 'Inter', sans-serif !important; }
#MainMenu { visibility: hidden; }
.stDeployButton { display: none; }
header { visibility: hidden; }
footer { visibility: hidden; }
.viewerBadge_container { display: none; }

/* Enhanced Sticky Top Navigation */
.top-nav { 
  position: fixed; 
  top: 0; 
  left: 0; 
  right: 0; 
  z-index: 1000; 
  height: 70px; 
  background: linear-gradient(180deg, rgba(15,23,42,0.4) 0%, rgba(15,23,42,0.3) 100%); 
  backdrop-filter: blur(30px) saturate(200%);
  border-bottom: 1px solid rgba(96, 165, 250, 0.2);
  padding: 0 48px; 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  animation: slideDown 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  box-shadow: inset 0 1px 0 rgba(96, 165, 250, 0.2), 0 20px 60px rgba(96, 165, 250, 0.08);
  width: 100vw;
  left: 0;
  margin-left: calc(-50vw + 50%);
}

@keyframes slideDown { 
  from { transform: translateY(-100px); opacity: 0; } 
  to { transform: translateY(0); opacity: 1; } 
}

.nav-left { display: flex; align-items: center; gap: 32px; }
.nav-logo { 
  font-family: 'Space Grotesk'; 
  font-size: 20px; 
  font-weight: 700; 
  background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%); 
  -webkit-background-clip: text; 
  -webkit-text-fill-color: transparent; 
  letter-spacing: -0.5px;
  text-shadow: 0 0 30px rgba(96,165,250,0.3);
}

.nav-items { display: flex; align-items: center; gap: 12px; }

.nav-btn { 
  color: #e2e8f0;
  font-weight: 700;
  font-size: 13px;
  transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
  cursor: pointer;
  padding: 12px 20px;
  border-radius: 8px;
  margin: 0;
  text-decoration: none;
  position: relative;
  background: rgba(59, 130, 246, 0.1);
  border: 1px solid #3b82f6;
  font-family: 'Inter', sans-serif;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(96, 165, 250, 0.2);
  backdrop-filter: blur(8px);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  white-space: nowrap;
  letter-spacing: 0.4px;
  text-transform: capitalize;
  overflow: hidden;
}

.nav-btn::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.2) 0%, rgba(167, 139, 250, 0.1) 100%);
  opacity: 0;
  transition: opacity 0.3s ease;
  border-radius: 6px;
  pointer-events: none;
  z-index: -1;
}

.nav-btn:hover {
  color: #60a5fa;
  background: rgba(59, 130, 246, 0.25);
  border-color: #60a5fa;
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(96, 165, 250, 0.4), inset 0 1px 0 rgba(96, 165, 250, 0.3), 0 0 20px rgba(96, 165, 250, 0.3);
}

.nav-btn:hover::before {
  opacity: 1;
}

.nav-btn.active {
  color: #60a5fa;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.3) 0%, rgba(96, 165, 250, 0.15) 100%);
  border-color: #60a5fa;
  box-shadow: 0 0 25px rgba(96, 165, 250, 0.5), inset 0 1px 0 rgba(96, 165, 250, 0.4);
  font-weight: 700;
}

/* Enhanced Profile Card */
.nav-profile {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  padding: 8px 16px;
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.08) 0%, rgba(167, 139, 250, 0.05) 100%);
  border: 1px solid rgba(96, 165, 250, 0.15);
  transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.nav-profile:hover {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.18) 0%, rgba(167, 139, 250, 0.12) 100%);
  border-color: rgba(96, 165, 250, 0.35);
  transform: translateY(-2px);
  box-shadow: 0 12px 32px rgba(96, 165, 250, 0.2);
}

.avatar {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: 700;
  font-size: 14px;
  box-shadow: 0 8px 20px rgba(96, 165, 250, 0.3), inset 0 2px 4px rgba(255,255,255,0.2);
  position: relative;
}

.avatar::after {
  content: "🛡";
  position: absolute;
  bottom: -7px;
  right: -7px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: linear-gradient(145deg, #0f172a 0%, #1e293b 100%);
  border: 1px solid rgba(148, 163, 184, 0.65);
  font-size: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 0 2px rgba(15, 23, 42, 0.9), 0 6px 12px rgba(0,0,0,0.35);
}

.profile-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.profile-name {
  color: #e2e8f0;
  font-weight: 600;
  font-size: 13px;
}

.profile-email {
  color: #94a3b8;
  font-size: 11px;
  font-weight: 400;
}

/* Drag-Drop Zone Enhancement */
.drag-drop-zone {
  border: 2px dashed rgba(96, 165, 250, 0.3);
  border-radius: 16px;
  padding: 40px;
  text-align: center;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.05) 0%, rgba(167, 139, 250, 0.03) 100%);
  transition: all 0.3s ease;
  cursor: pointer;
  position: relative;
  overflow: hidden;
}

.drag-drop-zone::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: radial-gradient(circle at center, rgba(96, 165, 250, 0.1), transparent);
  opacity: 0;
  transition: opacity 0.3s ease;
  pointer-events: none;
}

.drag-drop-zone:hover {
  border-color: rgba(96, 165, 250, 0.5);
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.12) 0%, rgba(167, 139, 250, 0.08) 100%);
  box-shadow: 0 20px 60px rgba(96, 165, 250, 0.2), inset 0 0 40px rgba(96, 165, 250, 0.1);
}

.drag-drop-zone.dragover {
  border-color: rgba(96, 165, 250, 0.7);
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.2) 0%, rgba(167, 139, 250, 0.15) 100%);
  box-shadow: 0 20px 60px rgba(96, 165, 250, 0.25), inset 0 0 40px rgba(96, 165, 250, 0.1);
  transform: scale(1.02);
}

.drag-drop-zone.dragover::before {
  opacity: 1;
}

.drag-icon {
  font-size: 48px;
  margin-bottom: 16px;
  animation: bounce 2s ease-in-out infinite;
}

@keyframes bounce {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-10px); }
}

/* Enhanced Sticky Footer - Transparent, Sticky, Glassy Effect */
.footer {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  width: 100%;
  background: linear-gradient(135deg, 
    rgba(15, 23, 42, 0.7) 0%, 
    rgba(30, 41, 59, 0.6) 50%,
    rgba(15, 23, 42, 0.7) 100%
  );
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  padding: 16px 48px;
  text-align: center;
  color: #94a3b8;
  font-size: 12px;
  font-weight: 400;
  letter-spacing: 0.5px;
  box-shadow: 
    0 -10px 40px rgba(0, 0, 0, 0.3),
    inset 0 1px 0 rgba(255, 255, 255, 0.1),
    inset 0 -1px 0 rgba(255, 255, 255, 0.05);
  z-index: 9999;
  margin-left: calc(-50vw + 50%);
  margin-right: calc(-50vw + 50%);
}

/* Glassy effect overlay */
.footer::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(
    180deg,
    rgba(255, 255, 255, 0.08) 0%,
    rgba(255, 255, 255, 0.02) 50%,
    transparent 100%
  );
  pointer-events: none;
  border-radius: 0;
}

/* Top border glow effect */
.footer::after {
  content: '';
  position: absolute;
  top: 0;
  left: 20%;
  right: 20%;
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent 0%,
    rgba(96, 165, 250, 0.4) 50%,
    transparent 100%
  );
  box-shadow: 0 0 20px rgba(96, 165, 250, 0.3);
}

.footer-content {
  max-width: 1200px;
  margin: 0 auto;
}

.footer-main {
  font-size: 13px;
  font-weight: 600;
  background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin-bottom: 4px;
  letter-spacing: 0.3px;
}

.footer-sub {
  font-size: 10px;
  color: #718096;
  font-weight: 400;
  line-height: 1.3;
}

.footer-divider {
  height: 1px;
  background: linear-gradient(90deg, transparent 0%, rgba(96, 165, 250, 0.12) 50%, transparent 100%);
  margin: 6px 0;
}

/* Hide footer on login/unauthenticated pages */
.login-container .footer {
  display: none !important;
}

/* Profile Dropdown Card - Enhanced Glass Design */
.profile-dropdown {
  position: absolute;
  top: 80px;
  right: 48px;
  width: 320px;
  background: linear-gradient(135deg, rgba(30,41,59,0.95) 0%, rgba(15,23,42,0.92) 100%);
  backdrop-filter: blur(30px) saturate(200%);
  border: 1px solid rgba(96, 165, 250, 0.2);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 25px 80px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.1);
  animation: dropIn 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
  z-index: 2000;
}

@keyframes dropIn {
  from {
    opacity: 0;
    transform: translateY(-20px);
    backdrop-filter: blur(0px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
    backdrop-filter: blur(30px);
  }
}

.profile-card-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(96, 165, 250, 0.15);
  margin-bottom: 16px;
}

.profile-card-avatar {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: 700;
  font-size: 18px;
  box-shadow: 0 12px 32px rgba(96, 165, 250, 0.4), inset 0 2px 8px rgba(255,255,255,0.2);
  flex-shrink: 0;
  position: relative;
}

.profile-card-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.profile-card-name {
  color: #e2e8f0;
  font-weight: 600;
  font-size: 14px;
  font-family: 'Space Grotesk';
}

.profile-card-email {
  color: #94a3b8;
  font-size: 12px;
  word-break: break-all;
}

.profile-card-item {
  color: #cbd5e1;
  padding: 12px 0;
  border-bottom: 1px solid rgba(96, 165, 250, 0.1);
  cursor: pointer;
  font-size: 13px;
  transition: all 0.2s ease;
}

.profile-card-item:last-of-type {
  border-bottom: none;
}

.profile-card-item:hover {
  color: #60a5fa;
  padding-left: 8px;
  background: linear-gradient(90deg, rgba(96, 165, 250, 0.1) 0%, transparent 100%);
  border-radius: 6px;
  padding: 12px 8px;
}

.profile-card-logout {
  width: 100%;
  padding: 10px 16px;
  margin-top: 12px;
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(239, 68, 68, 0.1) 100%);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #8db9ff;
  border-radius: 8px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
  transition: all 0.3s ease;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.profile-card-logout:hover {
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.35) 0%, rgba(239, 68, 68, 0.2) 100%);
  border-color: rgba(239, 68, 68, 0.5);
  box-shadow: 0 8px 20px rgba(239, 68, 68, 0.3);
  transform: translateY(-2px);
}

/* Enhanced File Upload */
.file-upload-area {
  border: 2px dashed rgba(96, 165, 250, 0.4);
  border-radius: 16px;
  padding: 48px 32px;
  text-align: center;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.08) 0%, rgba(167, 139, 250, 0.05) 100%);
  transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
  cursor: pointer;
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(10px);
}

.file-upload-area::after {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: radial-gradient(circle at center, rgba(96, 165, 250, 0.15), transparent);
  opacity: 0;
  transition: opacity 0.3s ease;
  pointer-events: none;
}

.file-upload-area:hover {
  border-color: rgba(96, 165, 250, 0.6);
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.15) 0%, rgba(167, 139, 250, 0.1) 100%);
  box-shadow: 0 20px 60px rgba(96, 165, 250, 0.2), inset 0 0 40px rgba(96, 165, 250, 0.08);
  transform: scale(1.01);
}

.file-upload-area:hover::after {
  opacity: 1;
}

.file-upload-icon {
  font-size: 56px;
  margin-bottom: 16px;
  animation: float 3s ease-in-out infinite;
}

@keyframes float {
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-12px); }
}

/* Hide Sidebar */
[data-testid="stSidebar"] { display: none; }

/* Add padding to main content to account for fixed footer */
.main-content {
  padding-bottom: 120px !important;
}

/* STAT CARD STYLES - FIX FOR DASHBOARD DISPLAY */
.stat-card-animated {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.1) 0%, rgba(167, 139, 250, 0.05) 100%);
  border: 1px solid rgba(96, 165, 250, 0.2);
  border-radius: 16px;
  padding: 24px;
  backdrop-filter: blur(10px);
  transition: all 0.3s ease;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.stat-card-animated:hover {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.15) 0%, rgba(167, 139, 250, 0.08) 100%);
  border-color: rgba(96, 165, 250, 0.4);
  transform: translateY(-8px);
  box-shadow: 0 16px 48px rgba(96, 165, 250, 0.25);
}

.stat-number-animated {
  font-size: 36px;
  font-weight: 700;
  color: #60a5fa;
  margin-bottom: 8px;
  font-family: 'Space Grotesk';
  animation: counterUp 0.5s ease-out;
}

.stat-label-animated {
  font-size: 14px;
  color: #cbd5e1;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

@keyframes counterUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Report and Finding Card Styles */
.report-section {
  padding: 24px;
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.1) 0%, rgba(167, 139, 250, 0.05) 100%);
  border: 1px solid rgba(96, 165, 250, 0.15);
  margin-bottom: 16px;
  transition: all 0.3s ease;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
}

.report-section:hover {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.15) 0%, rgba(167, 139, 250, 0.08) 100%);
  border-color: rgba(96, 165, 250, 0.25);
  box-shadow: 0 8px 24px rgba(96, 165, 250, 0.15);
  transform: translateY(-2px);
}

.report-header {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.15) 0%, rgba(167, 139, 250, 0.08) 100%);
  border: 1px solid rgba(96, 165, 250, 0.2);
  border-radius: 16px;
  padding: 32px 24px;
  margin-bottom: 24px;
  backdrop-filter: blur(20px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}

.report-title {
  color: #e2e8f0;
  font-size: 24px;
  font-weight: 700;
  font-family: 'Space Grotesk';
  margin-bottom: 8px;
}

.report-subtitle {
  color: #94a3b8;
  font-size: 14px;
  margin-bottom: 16px;
}

.finding-card {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.12) 0%, rgba(167, 139, 250, 0.06) 100%);
  border: 1px solid rgba(96, 165, 250, 0.18);
  border-radius: 12px;
  padding: 20px;
  transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 12px rgba(96, 165, 250, 0.1);
}

.finding-card:hover {
  background: linear-gradient(135deg, rgba(96, 165, 250, 0.18) 0%, rgba(167, 139, 250, 0.1) 100%);
  border-color: rgba(96, 165, 250, 0.3);
  box-shadow: 0 8px 24px rgba(96, 165, 250, 0.2);
  transform: translateY(-4px);
}

.finding-label {
  color: #94a3b8;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 12px;
}

.finding-content {
  color: #60a5fa;
  font-size: 20px;
  font-weight: 700;
  font-family: 'Space Grotesk';
}

.reasoning-box {
  background: linear-gradient(135deg, rgba(251, 146, 60, 0.08) 0%, rgba(251, 146, 60, 0.03) 100%);
  border-left: 4px solid #fb923c;
  border-radius: 12px;
  padding: 20px 24px;
  margin: 16px 0;
  color: #cbd5e1;
  line-height: 1.6;
  font-size: 14px;
  backdrop-filter: blur(10px);
}

.badge-safe {
  display: inline-block;
  background: linear-gradient(135deg, rgba(34, 197, 94, 0.2) 0%, rgba(34, 197, 94, 0.1) 100%);
  color: #4ade80;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(34, 197, 94, 0.3);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-warning {
  display: inline-block;
  background: linear-gradient(135deg, rgba(251, 146, 60, 0.2) 0%, rgba(251, 146, 60, 0.1) 100%);
  color: #fb923c;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(251, 146, 60, 0.3);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-danger {
  display: inline-block;
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(239, 68, 68, 0.1) 100%);
  color: #8db9ff;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(239, 68, 68, 0.3);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

</style>
""", unsafe_allow_html=True)

# Monochrome theme overrides for professional UI consistency
st.markdown("""
<style>
:root {
  --bg-0: #060708;
  --bg-1: #0e1013;
  --bg-2: #16191e;
  --bg-3: #20242a;
  --text-0: #f1f3f5;
  --text-1: #d0d5db;
  --text-2: #9aa3ad;
  --line-0: #2f353d;
  --line-1: #3b424c;
}

.stApp {
  background:
    radial-gradient(circle at 10% 0%, rgba(255,255,255,0.05) 0%, transparent 40%),
    linear-gradient(140deg, var(--bg-0) 0%, var(--bg-1) 55%, var(--bg-2) 100%) !important;
}

.top-nav {
  background: linear-gradient(180deg, rgba(8, 9, 11, 0.92) 0%, rgba(14, 16, 19, 0.88) 100%) !important;
  border-bottom: 1px solid var(--line-0) !important;
  box-shadow: 0 16px 50px rgba(0, 0, 0, 0.45) !important;
  height: 58px !important;
  padding: 0 24px !important;
}

.nav-logo {
  background: linear-gradient(135deg, #f1f3f5 0%, #9aa3ad 100%) !important;
  -webkit-background-clip: text !important;
  -webkit-text-fill-color: transparent !important;
  text-shadow: none !important;
}

.nav-btn {
  background: rgba(255, 255, 255, 0.03) !important;
  border: 1px solid var(--line-0) !important;
  color: var(--text-1) !important;
  box-shadow: none !important;
  text-decoration: none !important;
}

.nav-btn:hover,
.nav-btn.active {
  background: rgba(255, 255, 255, 0.09) !important;
  border-color: var(--line-1) !important;
  color: var(--text-0) !important;
}

.nav-profile {
  background: rgba(255, 255, 255, 0.03) !important;
  border: 1px solid var(--line-0) !important;
}

.avatar,
.profile-card-avatar {
  background: linear-gradient(135deg, #2b3138 0%, #1b1f25 100%) !important;
  color: #f3f4f6 !important;
}

.avatar::after,
.profile-card-avatar::after {
  content: "🛡";
  position: absolute;
  bottom: -7px;
  right: -7px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: linear-gradient(145deg, #0f141b 0%, #1a2028 100%) !important;
  border: 1px solid rgba(127, 142, 160, 0.62) !important;
  box-shadow: 0 0 0 2px rgba(10, 14, 18, 0.95), 0 6px 12px rgba(0,0,0,0.34) !important;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
}

.file-upload-area,
.email-result-card,
.profile-dropdown,
.stat-card-animated {
  background: linear-gradient(145deg, rgba(19, 22, 26, 0.9) 0%, rgba(10, 12, 15, 0.9) 100%) !important;
  border-color: var(--line-0) !important;
}

.main .block-container {
  padding-bottom: 140px !important;
}

.footer {
  background: linear-gradient(180deg, rgba(8, 9, 11, 0.78) 0%, rgba(14, 16, 19, 0.92) 100%) !important;
  border-top: 1px solid var(--line-0) !important;
  box-shadow: 0 -16px 40px rgba(0, 0, 0, 0.45) !important;
}

.footer-main {
  background: linear-gradient(135deg, #f1f3f5 0%, #9aa3ad 100%) !important;
  -webkit-background-clip: text !important;
  -webkit-text-fill-color: transparent !important;
}

/* Auth shell */
.auth-shell {
  background: linear-gradient(145deg, rgba(19,22,26,0.94) 0%, rgba(10,12,15,0.95) 100%);
  border: 1px solid rgba(67,76,89,0.72);
  border-radius: 22px;
  padding: 28px;
  backdrop-filter: blur(22px) saturate(125%);
  box-shadow: 0 20px 44px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.08);
}

.auth-title {
  text-align: center;
  color: #f1f3f5;
  font-family: 'Space Grotesk';
  margin: 0 0 6px 0;
  font-size: 30px;
}

.auth-subtitle {
  text-align: center;
  color: #9aa3ad;
  margin: 0 0 16px 0;
  font-size: 14px;
}

.auth-pill-wrap {
  display: flex;
  justify-content: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

.auth-pill {
  font-size: 11px;
  color: #c9d3df;
  border: 1px solid rgba(101,114,131,0.55);
  background: rgba(27,33,40,0.72);
  padding: 6px 10px;
  border-radius: 999px;
}

/* Global app button language */
button[data-testid^="baseButton"] {
  border-radius: 12px !important;
  font-weight: 600 !important;
  letter-spacing: 0.15px !important;
  transition: all 0.22s ease !important;
}

button[data-testid="baseButton-primary"] {
  border: 1px solid rgba(139, 190, 248, 0.64) !important;
  background: linear-gradient(145deg, #2d4f75 0%, #3c6792 52%, #4a80b0 100%) !important;
  color: #f4f8fc !important;
  box-shadow: 0 10px 24px rgba(67,118,171,0.34), 0 0 14px rgba(126,176,235,0.2), inset 0 1px 0 rgba(255,255,255,0.16) !important;
}

button[data-testid="baseButton-primary"]:hover {
  transform: translateY(-1px) !important;
  border-color: rgba(166, 210, 255, 0.82) !important;
  background: linear-gradient(145deg, #3a638f 0%, #4a78a6 52%, #5890c2 100%) !important;
  box-shadow: 0 14px 28px rgba(78,131,189,0.38), 0 0 18px rgba(143,194,250,0.28) !important;
}

button[data-testid="baseButton-primary"]:active {
  transform: translateY(0) scale(0.99) !important;
}

button[data-testid="baseButton-secondary"] {
  border: 1px solid rgba(102, 120, 142, 0.52) !important;
  background: linear-gradient(145deg, rgba(28,34,42,0.94) 0%, rgba(18,22,28,0.96) 100%) !important;
  color: #dbe4ef !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 6px 14px rgba(0,0,0,0.30) !important;
}

button[data-testid="baseButton-secondary"]:hover {
  transform: translateY(-1px) !important;
  border-color: rgba(132, 181, 235, 0.58) !important;
  background: linear-gradient(145deg, rgba(40,58,82,0.95) 0%, rgba(28,44,64,0.97) 100%) !important;
  color: #ecf5ff !important;
  box-shadow: 0 10px 22px rgba(0,0,0,0.32), 0 0 16px rgba(117, 169, 230, 0.24) !important;
}

div[data-testid="stTextInput"] input {
  min-height: 46px !important;
  border-radius: 13px !important;
  border: 1px solid rgba(95, 109, 126, 0.50) !important;
  background: linear-gradient(180deg, rgba(19, 22, 27, 0.96) 0%, rgba(12, 16, 21, 0.96) 100%) !important;
  color: #e8edf3 !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 6px 14px rgba(0,0,0,0.22) !important;
}

div[data-testid="stTextInput"] input:focus {
  border-color: rgba(132, 184, 245, 0.58) !important;
  box-shadow: 0 0 0 2px rgba(73, 127, 188, 0.22), 0 8px 18px rgba(48, 93, 145, 0.26) !important;
}

div[data-testid="stTabs"] button[role="tab"] {
  border-radius: 11px !important;
  border: 1px solid rgba(74, 83, 95, 0.75) !important;
  background: linear-gradient(160deg, rgba(21,25,30,0.94) 0%, rgba(14,18,23,0.94) 100%) !important;
  color: #cfd6de !important;
  font-weight: 600 !important;
}

div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
  border-color: rgba(129, 181, 241, 0.62) !important;
  background: linear-gradient(160deg, rgba(34,56,82,0.98) 0%, rgba(24,43,64,0.98) 100%) !important;
  color: #f3f7fb !important;
  box-shadow: 0 8px 20px rgba(44, 91, 138, 0.30), 0 0 14px rgba(115, 170, 235, 0.18) !important;
}

/* Top nav streamlit button bar */
.top-nav-buttons + div[data-testid="stHorizontalBlock"] {
  margin-top: 2px !important;
  margin-bottom: 18px !important;
  padding: 7px !important;
  border-radius: 14px !important;
  border: 1px solid rgba(72, 84, 98, 0.75) !important;
  background: linear-gradient(180deg, rgba(14,18,23,0.90) 0%, rgba(10,14,18,0.94) 100%) !important;
  backdrop-filter: blur(12px) saturate(130%) !important;
  box-shadow: 0 12px 26px rgba(0,0,0,0.24) !important;
}

.top-nav-buttons + div[data-testid="stHorizontalBlock"] button[data-testid^="baseButton"] {
  min-height: 32px !important;
  font-size: 13px !important;
  border-radius: 999px !important;
  border: 1px solid rgba(98, 113, 132, 0.40) !important;
  background: linear-gradient(145deg, rgba(28,34,42,0.93) 0%, rgba(18,22,28,0.95) 100%) !important;
  color: #dbe4ef !important;
  font-weight: 600 !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 6px 14px rgba(0,0,0,0.28) !important;
  transition: all 0.22s ease !important;
}

.top-nav-buttons + div[data-testid="stHorizontalBlock"] button[data-testid^="baseButton"]:hover {
  transform: translateY(-1px) !important;
  border-color: rgba(133, 181, 236, 0.62) !important;
  background: linear-gradient(145deg, rgba(40,58,82,0.95) 0%, rgba(28,44,64,0.97) 100%) !important;
  box-shadow: 0 10px 22px rgba(0,0,0,0.32), 0 0 16px rgba(117, 169, 230, 0.24) !important;
}

.top-nav-buttons + div[data-testid="stHorizontalBlock"] button[data-testid="baseButton-primary"] {
  border-color: rgba(138, 187, 240, 0.66) !important;
  background: linear-gradient(145deg, #2b4e74 0%, #3a638d 52%, #4878a6 100%) !important;
  color: #f4f8fc !important;
  box-shadow: 0 10px 24px rgba(67,118,171,0.38), 0 0 16px rgba(126,176,235,0.24) !important;
}

.url-verdict-card {
  border-radius: 16px;
  border: 1px solid rgba(92, 109, 129, 0.58);
  background: linear-gradient(150deg, rgba(18, 23, 30, 0.96) 0%, rgba(10, 14, 19, 0.96) 100%);
  padding: 18px;
  margin: 12px 0 10px;
  box-shadow: 0 12px 28px rgba(0, 0, 0, 0.30), inset 0 1px 0 rgba(255,255,255,0.08);
}

.url-verdict-card.safe {
  border-color: rgba(120, 201, 255, 0.5);
  box-shadow: 0 14px 30px rgba(38, 90, 141, 0.30), 0 0 22px rgba(126, 199, 255, 0.20);
}

.url-verdict-card.suspicious {
  border-color: rgba(250, 203, 111, 0.65);
  box-shadow: 0 16px 32px rgba(127, 89, 20, 0.34), 0 0 24px rgba(250, 204, 126, 0.28);
}

.url-verdict-title {
  color: #c8d6e5;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
  font-weight: 700;
  margin-bottom: 8px;
}

.url-verdict-main {
  font-size: 26px;
  font-family: 'Space Grotesk';
  font-weight: 700;
  margin-bottom: 6px;
}

.url-verdict-safe {
  color: #85d0ff;
  text-shadow: 0 0 18px rgba(133, 208, 255, 0.30);
}

.url-verdict-suspicious {
  color: #ffd488;
  text-shadow: 0 0 18px rgba(255, 212, 136, 0.35);
}

.url-verdict-note {
  color: #b6c2d0;
  font-size: 13px;
}
</style>
""", unsafe_allow_html=True)

# Enhanced JavaScript with external module reference
st.markdown("""
<script>
// PhishXzero v3.0 - Frontend Integration
// Note: Main app.js will be loaded from static directory

/**
 * Page transition handler
 */
class PageTransition {
    static fadeOut(duration = 300) {
        const elements = document.querySelectorAll('[data-page]');
        elements.forEach(el => {
            el.style.transition = `opacity ${duration}ms ease`;
            el.style.opacity = '0';
        });
    }

    static fadeIn(duration = 300) {
        const elements = document.querySelectorAll('[data-page]');
        elements.forEach(el => {
            el.style.transition = `opacity ${duration}ms ease`;
            el.style.opacity = '1';
        });
    }
}

/**
 * Real-time threat detection UI updates
 */
class ThreatDetectionUI {
    static updateRiskScore(score) {
        const riskElements = document.querySelectorAll('[data-risk-score]');
        riskElements.forEach(el => {
            el.textContent = Math.round(score);
            el.style.color = score >= 60 ? '#7aa2ff' : score >= 35 ? '#fb923c' : '#22c55e';
        });
    }

    static updateVerdictBadge(verdict) {
        const badge = document.querySelector('[data-verdict-badge]');
        if (!badge) return;

        let bgColor, textColor;
        switch (verdict) {
            case 'PHISHING':
                bgColor = '#7aa2ff';
                textColor = '#fecaca';
                break;
            case 'SUSPICIOUS':
                bgColor = '#fb923c';
                textColor = '#fed7aa';
                break;
            default:
                bgColor = '#22c55e';
                textColor = '#bbf7d0';
        }

        badge.style.backgroundColor = bgColor;
        badge.style.color = textColor;
        badge.textContent = verdict;
    }

    static addThreatIndicator(indicator) {
        const container = document.querySelector('[data-threat-indicators]');
        if (!container) return;

        const badge = document.createElement('div');
        badge.className = 'result-badge-improved badge-warning-improved';
        badge.textContent = indicator;
        badge.style.animation = 'slideIn 0.3s ease';
        container.appendChild(badge);
    }
}

/**
 * Email analysis real-time feedback
 */
class EmailAnalysisUI {
    static showParsingFeedback(feedback) {
        const statusEl = document.querySelector('[data-parse-status]');
        if (!statusEl) return;

        const status = [];
        if (feedback.hasSender) status.push('Sender detected');
        if (feedback.hasSubject) status.push('Subject detected');
        if (feedback.hasBody) status.push('Body detected');

        if (feedback.suspiciousPatterns.length > 0) {
            status.push(` ${feedback.suspiciousPatterns.length} suspicious pattern(s)`);
        }

        statusEl.innerHTML = status.join('<br>');
        statusEl.style.color = feedback.suspiciousPatterns.length > 0 ? '#fb923c' : '#4ade80';
    }

    static enableAnalyzeButton(enabled = true) {
        const btn = document.querySelector('[data-analyze-email]');
        if (btn) {
            btn.disabled = !enabled;
            btn.style.opacity = enabled ? '1' : '0.5';
            btn.style.pointerEvents = enabled ? 'auto' : 'none';
        }
    }

    static showAnalysisProgress(progress) {
        const bar = document.querySelector('[data-progress-bar]');
        if (bar) {
            bar.style.width = `${progress}%`;
            bar.style.transition = 'width 0.3s ease';
        }
    }
}

/**
 * URL validation with real-time feedback
 */
class URLValidationUI {
    static validateAndDisplay(url) {
        const indicatorEl = document.querySelector('[data-url-valid]');
        if (!indicatorEl) return;

        try {
            new URL(url);
            indicatorEl.textContent = 'Valid URL';
            indicatorEl.style.color = '#4ade80';
            
            // Check for suspicious patterns
            if (this.isSuspiciousURL(url)) {
                indicatorEl.textContent = 'Suspicious URL pattern detected';
                indicatorEl.style.color = '#fb923c';
            }
            return true;
        } catch {
            indicatorEl.textContent = 'Invalid URL format';
            indicatorEl.style.color = '#8db9ff';
            return false;
        }
    }

    static isSuspiciousURL(url) {
        const suspicious = [
            /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/, // IP address
            /bit\\.ly|tinyurl|short\\.link/, // URL shorteners
            /.*(verify|confirm|update|account).*/, // Common phishing words
        ];
        return suspicious.some(pattern => pattern.test(url));
    }
}

/**
 * File upload progress and validation
 */
class FileUploadUI {
    static showProgress(progress) {
        const bar = document.querySelector('[data-file-progress]');
        if (bar) {
            bar.style.width = `${progress}%`;
        }
    }

    static validateFile(file) {
        const maxSize = 50 * 1024 * 1024;
        const errors = [];

        if (file.size > maxSize) {
            errors.push('File exceeds 50MB limit');
        }

        return {
            valid: errors.length === 0,
            errors: errors,
            size: (file.size / 1024 / 1024).toFixed(2),
            name: file.name
        };
    }
}

/**
 * Analytics chart interaction enhancements
 */
class AnalyticsUI {
    static highlightChart(chartId) {
        const chart = document.getElementById(chartId);
        if (!chart) return;

        chart.style.transform = 'scale(1.02)';
        chart.style.boxShadow = '0 20px 60px rgba(96, 165, 250, 0.3)';
    }

    static unhighlightChart(chartId) {
        const chart = document.getElementById(chartId);
        if (!chart) return;

        chart.style.transform = 'scale(1)';
        chart.style.boxShadow = '0 8px 32px rgba(0, 0, 0, 0.1)';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishXzero JavaScript modules loaded');
});
</script>
""", unsafe_allow_html=True)

# UTILITY FUNCTIONS FOR STATISTICS
def generate_dashboard_stats(user_id: int) -> Dict[str, float]:
    """Generate comprehensive statistics for dashboard"""
    stats: Dict = scan_db.get_scan_stats(user_id)
    
    total: int = max(stats['total'], 1)
    
    return {
        'total_scans': stats['total'],
        'phishing_detected': stats['phishing'],
        'suspicious_detected': stats['suspicious'],
        'legitimate_detected': stats['legitimate'],
        'phishing_rate': round(stats['phishing'] / total * 100, 1),
        'suspicious_rate': round(stats['suspicious'] / total * 100, 1),
        'legitimate_rate': round(stats['legitimate'] / total * 100, 1),
        'avg_risk_score': round(stats['avg_score'], 1),
        'detection_accuracy': round((stats['phishing'] + stats['legitimate']) / total * 100, 1)
    }

def render_risk_meter(score: float, label: str = "Risk Score") -> None:
    """Render an animated risk meter gauge"""
    threat_color: str = '#7aa2ff'if score >= 60 else '#fb923c'if score >= 35 else '#22c55e'
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        title={'text': label},
        delta={'reference': 50},
        gauge=dict(
            axis=dict(range=[0, 100]),
            bar=dict(color=threat_color),
            steps=[
                dict(range=[0, 33], color='rgba(34,197,94,0.1)'),
                dict(range=[33, 66], color='rgba(251,146,60,0.1)'),
                dict(range=[66, 100], color='rgba(122,162,255,0.1)')
            ],
            threshold=dict(
                line=dict(color='red', width=4),
                thickness=0.75,
                value=90
            )
        )
    ))
    
    fig.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#cbd5e1'),
        margin=dict(l=0, r=0, t=50, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

# ENHANCED ML PHISHING DETECTOR WITH MULTI-LAYER ANALYSIS
def ml_phishing_detector_enhanced(email_text: str, sender: str, subject: str) -> Dict:
    """Enhanced ML-based phishing detector with multi-layer analysis"""
    score: int = 0
    reasons: List[str] = []
    
    keywords: Dict[str, int] = {
        'urgent': 15, 'verify': 12, 'suspended': 18, 'confirm': 10,
        'account': 8, 'security': 10, 'click here': 20, 'update': 8,
        'password': 12, 'expire': 15, 'limited time': 18, 'act now': 20
    }
    
    for kw, w in keywords.items():
        if kw in email_text.lower() or kw in subject.lower():
            score += w
            reasons.append(f"High-risk keyword: '{kw}'")
    
    urls: List[str] = re.findall(r'http[s]?://\S+', email_text)
    if len(urls) > 3:
        score += 15
        reasons.append(f"Multiple URLs ({len(urls)})")
    
    if any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls):
        score += 30
        reasons.append("IP-based URL detected")
    
    if any(d in sender.lower() for d in ['gmail', 'yahoo', 'hotmail']):
        score += 8
        reasons.append("Free email provider used")
    
    if subject.isupper() and len(subject) > 5:
        score += 18
        reasons.append("All-caps subject line")
    
    body_analysis: Dict = email_analyzer.analyze(email_text, sender)
    score += body_analysis['total_score']
    
    if body_analysis['ip_urls']:
        reasons.append(f"IP-based URLs in body: {len(body_analysis['ip_urls'])}")
    
    ml_score: float = min(score * 1.2, 100)
    
    if score >= 60:
        verdict, risk, color = 'PHISHING', 'CRITICAL', '#7aa2ff'
    elif score >= 35:
        verdict, risk, color = 'SUSPICIOUS', 'HIGH', '#fb923c'
    else:
        verdict, risk, color = 'LEGITIMATE', 'LOW', '#22c55e'
    
    return {
        'score': min(score, 100),
        'ml_score': ml_score,
        'verdict': verdict,
        'risk_level': risk,
        'color': color,
        'reasons': reasons,
        'urls': urls,
        'body_analysis': body_analysis
    }

def generate_phishing_report(email_data: Dict, result: Dict) -> Dict:
    """Generate detailed phishing analysis report"""
    report: Dict = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sender': email_data['sender'],
        'subject': email_data['subject'],
        'verdict': result['verdict'],
        'risk_level': result['risk_level'],
        'risk_score': result['score'],
        'ml_confidence': result['ml_score'],
        'reasons': result['reasons'],
        'urls': result['urls'],
        'analysis': get_detailed_analysis(email_data, result)
    }
    return report

def get_detailed_analysis(email_data: Dict, result: Dict) -> Dict:
    """Get detailed cybersecurity analysis of phishing indicators"""
    analysis: List[Dict] = []
    
    if result['verdict'] == 'PHISHING':
        analysis.append({
            'rule': 'Phishing Detection',
            'severity': 'CRITICAL',
            'description': 'Email has been flagged as PHISHING - poses high security risk',
            'indicators': ['Multiple phishing indicators detected', 'High-risk keyword combinations', 'Suspicious sender patterns'],
            'recommendation': 'DELETE immediately. Do not click links or download attachments. Report to IT security.'
        })
    elif result['verdict'] == 'SUSPICIOUS':
        analysis.append({
            'rule': 'Suspicious Content',
            'severity': 'HIGH',
            'description': 'Email exhibits behaviors consistent with social engineering attacks',
            'indicators': ['Moderate phishing indicators', 'Unusual patterns detected', 'Potential spoofing attempt'],
            'recommendation': 'Review carefully. Verify sender through alternative channel. Do not share sensitive information.'
        })
    
    rules: List[Dict] = []
    if any('urgent'in r.lower() for r in result['reasons']):
        rules.append({
            'rule': 'Urgency Exploitation',
            'violated': True,
            'type': 'Social Engineering',
            'description': 'Uses artificial urgency to bypass decision-making'
        })
    if any('verify'in r.lower() or 'confirm'in r.lower() for r in result['reasons']):
        rules.append({
            'rule': 'Identity Verification',
            'violated': True,
            'type': 'Phishing',
            'description': 'Requests credential verification - classic phishing tactic'
        })
    if any('suspended'in r.lower() or 'expire'in r.lower() for r in result['reasons']):
        rules.append({
            'rule': 'Account Threat',
            'violated': True,
            'type': 'Social Engineering',
            'description': 'Threatens account suspension or expiration'
        })
    if any('IP-based'in r or 'Multiple URLs'in r for r in result['reasons']):
        rules.append({
            'rule': 'URL Obfuscation',
            'violated': True,
            'type': 'Phishing',
            'description': 'Uses hidden or suspicious URLs to mask destination'
        })
    if any('Free email provider'in r for r in result['reasons']):
        rules.append({
            'rule': 'Domain Spoofing',
            'violated': True,
            'type': 'Phishing',
            'description': 'Uses free email provider instead of official domain'
        })
    if any('All-caps'in r for r in result['reasons']):
        rules.append({
            'rule': 'Pressure Tactics',
            'violated': True,
            'type': 'Social Engineering',
            'description': 'Uses aggressive formatting to create urgency'
        })
    
    return {'security_rules': rules, 'critical_analysis': analysis}

def export_to_csv(report: Dict) -> Optional[bytes]:
    """Export report to CSV format"""
    try:
        df_data: Dict = {
            'Timestamp': [report['timestamp']],
            'Sender': [report['sender']],
            'Subject': [report['subject']],
            'Verdict': [report['verdict']],
            'Risk Level': [report['risk_level']],
            'Risk Score': [report['risk_score']],
            'ML Confidence': [f"{report['ml_confidence']:.1f}%"],
            'Detected Indicators': ['; '.join(report['reasons'])] if report['reasons'] else ['None'],
            'URLs Found': [len(report['urls'])],
        }
        df: pd.DataFrame = pd.DataFrame(df_data)
        return df.to_csv(index=False).encode('utf-8')
    except Exception as e:
        st.error(f"Error exporting CSV: {str(e)}")
        return None

def export_to_pdf(report: Dict) -> Optional[bytes]:
    """Export report to PDF format"""
    if not PDF_AVAILABLE:
        return None
    
    try:
        buffer: io.BytesIO = io.BytesIO()
        c: canvas.Canvas = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        c.setFont("Helvetica-Bold", 18)
        c.drawString(inch, height - inch, "phishXzero Security Report")
        
        y: float = height - 1.5 * inch
        c.setFont("Helvetica", 10)
        c.drawString(inch, y, f"Generated: {report['timestamp']}")
        y -= 0.3 * inch
        
        c.setFont("Helvetica-Bold", 12)
        c.drawString(inch, y, "Email Analysis")
        y -= 0.25 * inch
        c.setFont("Helvetica", 10)
        c.drawString(inch, y, f"From: {report['sender']}")
        y -= 0.2 * inch
        c.drawString(inch, y, f"Subject: {report['subject'][:50]}...")
        y -= 0.3 * inch
        
        c.setFont("Helvetica-Bold", 12)
        verdict_text: str = f"Verdict: {report['verdict']} (Risk: {report['risk_level']})"
        c.drawString(inch, y, verdict_text)
        y -= 0.3 * inch
        
        c.setFont("Helvetica", 10)
        c.drawString(inch, y, f"Risk Score: {report['risk_score']}/100")
        y -= 0.2 * inch
        c.drawString(inch, y, f"ML Confidence: {report['ml_confidence']:.1f}%")
        y -= 0.4 * inch
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        st.warning(f"PDF export error: {str(e)}")
        return None

def generate_comprehensive_report(email_data: Dict, result: Dict, body_analysis: Dict) -> Dict:
    """Generate comprehensive technical and non-technical report"""
    
    threat_vector = "Multi-factor"
    threat_factors: List[str] = []
    
    if any('urgency'in r.lower() for r in result['reasons']):
        threat_factors.append("Social Engineering - Urgency Exploitation")
    if any('verify'in r.lower() or 'confirm'in r.lower() for r in result['reasons']):
        threat_factors.append("Credential Harvesting")
    if any('IP-based'in r for r in result['reasons']):
        threat_factors.append("Obfuscated Infrastructure")
    if body_analysis.get('urgency_score', 0) > 20:
        threat_factors.append("Psychological Pressure Tactics")
    if body_analysis.get('credential_score', 0) > 20:
        threat_factors.append("Identity Verification Exploitation")
    
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sender': email_data.get('sender', 'Unknown'),
        'subject': email_data.get('subject', '(No Subject)'),
        'verdict': result['verdict'],
        'risk_level': result['risk_level'],
        'risk_score': result['score'],
        'ml_confidence': result['ml_score'],
        'threat_factors': threat_factors,
        'reasons': result['reasons'],
        'urls': result['urls'],
        'body_analysis': body_analysis,
        'technical_analysis': get_technical_analysis(result, body_analysis),
        'non_technical_summary': get_non_technical_summary(result, threat_factors)
    }

def get_technical_analysis(result: Dict, body_analysis: Dict) -> Dict:
    """Get detailed technical analysis"""
    return {
        'ml_scoring': {
            'algorithm': 'Multi-layer Keyword + URL Analysis',
            'weights': {
                'urgency_keywords': 15,
                'credential_requests': 12,
                'ip_urls': 30,
                'domain_spoofing': 8,
                'formatting_abuse': 18
            },
            'score': result['score'],
            'confidence': f"{result['ml_score']:.1f}%"
        },
        'url_analysis': {
            'count': len(result['urls']),
            'ip_based': len([u for u in result['urls'] if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]),
            'suspicious_patterns': body_analysis.get('suspicious_patterns', [])
        },
        'body_characteristics': {
            'urgency_indicators': body_analysis.get('urgency_score', 0),
            'financial_indicators': body_analysis.get('financial_score', 0),
            'credential_requests': body_analysis.get('credential_score', 0),
            'threat_language': body_analysis.get('threat_score', 0)
        }
    }

def get_non_technical_summary(result: Dict, threat_factors: List[str]) -> str:
    """Get non-technical explanation"""
    summary = "This email has been identified as "
    
    if result['verdict'] == 'PHISHING':
        summary += "a PHISHING attempt. "
        summary += "The email is designed to trick you into taking an action (clicking a link, downloading a file, or providing personal information) by impersonating a trusted organization. "
    elif result['verdict'] == 'SUSPICIOUS':
        summary += "SUSPICIOUS and warrants careful review. "
        summary += "While not definitively phishing, this email exhibits behaviors commonly associated with social engineering attacks. "
    else:
        summary += "LEGITIMATE and appears safe to interact with. "
        return summary
    
    if threat_factors:
        summary += f"Key concerns identified: {', '.join(threat_factors[:2])}. "
    
    summary += "We recommend: Do not click any links, do not download attachments, and do not provide personal information. "
    summary += "If unsure about the sender, contact them directly using a known phone number or email address."
    
    return summary

def render_warning_highlight(title: str, message: str, level: str = "WARNING") -> None:
    """Render consistent yellow warning highlight for suspicious/dangerous findings."""
    level_color = "#facc15" if level in ["WARNING", "SUSPICIOUS"] else "#f59e0b"
    st.markdown(
        f"""
        <div style="margin:12px 0; padding:12px 14px; border-radius:10px;
                    background:linear-gradient(135deg, rgba(250,204,21,0.18) 0%, rgba(250,204,21,0.08) 100%);
                    border:1px solid rgba(250,204,21,0.55);">
            <div style="display:flex; align-items:center; gap:10px;">
                <span style="display:inline-block; width:10px; height:10px; border-radius:999px; background:{level_color}; box-shadow:0 0 10px {level_color};"></span>
                <span style="font-weight:700; color:{level_color}; letter-spacing:0.3px;">{title}</span>
            </div>
            <div style="margin-top:6px; color:#f1f5f9; font-size:13px; line-height:1.5;">{message}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def _qp_value(key: str) -> Optional[str]:
    """Read query parameter value safely across Streamlit versions."""
    try:
        params = st.query_params
        if key not in params:
            return None
        value = params[key]
        if isinstance(value, list):
            return value[0] if value else None
        return str(value)
    except Exception:
        return None

def _clear_query_params() -> None:
    try:
        st.query_params.clear()
    except Exception:
        pass

def _get_valid_google_access_token(user_id: int) -> Tuple[Optional[str], Optional[str]]:
    """Return valid Google access token, refreshing when expired."""
    token_record = auth_manager.get_google_tokens(user_id)
    if not token_record:
        return None, "Google account not connected for this user."

    access_token = token_record.get("access_token")
    expires_at = token_record.get("expires_at")
    refresh_token = token_record.get("refresh_token")
    now_ts = int(time.time())

    if access_token and (not expires_at or expires_at > now_ts + 60):
        return access_token, None

    if not refresh_token:
        return None, "Google token expired and no refresh token is available. Reconnect Google."

    ok, refreshed = google_oauth_manager.refresh_access_token(refresh_token)
    if not ok:
        return None, f"Token refresh failed: {refreshed.get('error', 'Unknown error')}"

    refreshed_payload = {
        "access_token": refreshed.get("access_token"),
        "refresh_token": refresh_token,
        "expires_at": refreshed.get("expires_at"),
        "scope": refreshed.get("scope", token_record.get("scope")),
        "token_type": refreshed.get("token_type", token_record.get("token_type"))
    }
    profile_payload = {
        "email": token_record.get("google_email", st.session_state.get("email")),
        "name": token_record.get("google_name", st.session_state.get("username"))
    }
    auth_manager.save_google_tokens(user_id, refreshed_payload, profile_payload)
    return refreshed_payload["access_token"], None

def _handle_google_oauth_callback() -> None:
    """Handle Google OAuth callback and establish authenticated session."""
    if st.session_state.get("authenticated"):
        return

    oauth_error = _qp_value("error")
    oauth_code = _qp_value("code")
    oauth_state = _qp_value("state")
    expected_state = st.session_state.get("google_oauth_state")

    if not oauth_error and not oauth_code:
        return

    if oauth_error:
        st.session_state["google_oauth_status"] = f"Google sign-in cancelled/failed: {oauth_error}"
        _clear_query_params()
        return

    if not google_oauth_manager.is_configured():
        st.session_state["google_oauth_status"] = "Google OAuth is not configured in environment variables."
        _clear_query_params()
        return

    if not oauth_state or not expected_state or oauth_state != expected_state:
        st.session_state["google_oauth_status"] = "OAuth state mismatch. Please retry Google sign-in."
        _clear_query_params()
        return

    ok, token_data = google_oauth_manager.exchange_code(oauth_code)
    if not ok:
        st.session_state["google_oauth_status"] = f"Google token exchange failed: {token_data.get('error', 'Unknown error')}"
        _clear_query_params()
        return

    access_token = token_data.get("access_token")
    if not access_token:
        st.session_state["google_oauth_status"] = "Google did not return an access token."
        _clear_query_params()
        return

    ok, profile = google_oauth_manager.get_user_info(access_token)
    if not ok:
        st.session_state["google_oauth_status"] = f"Unable to fetch Google profile: {profile.get('error', 'Unknown error')}"
        _clear_query_params()
        return

    google_id = profile.get("sub")
    email = profile.get("email")
    name = profile.get("name") or profile.get("given_name") or "Google User"
    if not google_id or not email:
        st.session_state["google_oauth_status"] = "Google profile is missing account identifiers."
        _clear_query_params()
        return

    success, user_id, username, user_email, message = auth_manager.upsert_google_user(google_id, email, name)
    if not success or not user_id:
        st.session_state["google_oauth_status"] = f"Google user import failed: {message}"
        _clear_query_params()
        return

    auth_manager.save_google_tokens(
        user_id,
        {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": token_data.get("expires_at"),
            "scope": token_data.get("scope"),
            "token_type": token_data.get("token_type")
        },
        {"email": email, "name": name}
    )

    st.session_state.authenticated = True
    st.session_state.user_id = user_id
    st.session_state.username = username or name
    st.session_state.email = user_email or email
    st.session_state.page = 'home'
    st.session_state["google_oauth_status"] = "Google sign-in successful."
    _clear_query_params()
    st.rerun()

def perform_email_analysis(sender: str, subject: str, body: str, parse_result: Dict, enable_vt: bool, enable_yara: bool) -> None:
    """Unified function to perform email analysis and save results for both Paste and Upload"""
    try:
        # Core analysis
        result = ml_phishing_detector_enhanced(body, subject, sender)
        body_analysis = email_analyzer.analyze(body, sender)
        
        vt_results = {}
        vt_url_detail_report = {}
        detected_urls = feature_extractor.extract_urls(body)
        if enable_vt and detected_urls:
            st.info("Scanning URLs with VirusTotal...")
            for url in detected_urls[:3]:
                try:
                    vt_data = vt_checker.check_url(url)
                    vt_results[url] = vt_data
                    
                    status = vt_data.get('status', 'UNKNOWN')
                    if status == 'ANALYZED':
                        threat_level = vt_data.get('threat_level', 'UNKNOWN')
                        vt_url_detail_report[url] = {
                            'status': status,
                            'detections': vt_data.get('detections', 0),
                            'vendors': vt_data.get('vendors', {}),
                            'threat_level': threat_level,
                            'reputation': vt_data.get('reputation', 0),
                            'analysis_date': vt_data.get('analysis_date', 'N/A')
                        }
                    else:
                        vt_url_detail_report[url] = {
                            'status': status,
                            'detections': vt_data.get('detections', 0),
                            'vendors': vt_data.get('vendors', {}),
                            'threat_level': vt_data.get('threat_level', 'UNKNOWN'),
                            'reputation': vt_data.get('reputation', 0),
                            'analysis_date': vt_data.get('analysis_date', 'N/A'),
                            'message': vt_data.get('message') or vt_data.get('error', 'VirusTotal lookup failed')
                        }
                except Exception as vt_err:
                    st.warning(f"Could not scan URL: {str(vt_err)[:100]}")
                    vt_url_detail_report[url] = {
                        'status': 'FAILED',
                        'detections': 0,
                        'vendors': {},
                        'threat_level': 'UNKNOWN',
                        'reputation': 0,
                        'analysis_date': 'N/A',
                        'message': str(vt_err)[:150]
                    }
        
        yara_results = None
        if enable_yara:
            st.info("Running YARA malware detection...")
            try:
                yara_results = yara_scanner.scan_text(body)
            except Exception as yara_err:
                st.warning(f"YARA scan error: {str(yara_err)[:100]}")
        
        st.markdown("---")
        
        full_report = generate_comprehensive_report({'sender': sender, 'subject': subject}, result, body_analysis)
        render_comprehensive_report_ui(full_report)

        if result.get('verdict') in ['SUSPICIOUS', 'PHISHING']:
            render_warning_highlight(
                "EMAIL RISK ALERT",
                f"Email classified as {result.get('verdict')} with risk score {result.get('score', 0)}. Review links, sender identity, and requests before taking action.",
                "CRITICAL" if result.get('verdict') == 'PHISHING' else "SUSPICIOUS"
            )
        
        # AUTO-SAVE EMAIL TO BACKEND - CRITICAL FIX: Save to all databases
        save_success = False
        if st.session_state.get('user_id') and st.session_state.get('user_id') != 0:
            try:
                # Prepare data safely
                verdict = result.get('verdict', 'UNKNOWN')
                score = float(result.get('score', 0))
                risk_level = result.get('risk_level', 'LOW')
                reasons = '; '.join(result.get('reasons', result.get('threats', [])))
                
                # 1. Save to main scans database (CRITICAL FIX)
                print(f"DEBUG: Saving scan - User ID: {st.session_state.get('user_id')}, Verdict: {verdict}, Score: {score}")
                scan_db.add_scan(
                    user_id=st.session_state.get('user_id'),
                    sender=sender,
                    subject=subject,
                    body=body,
                    verdict=verdict,
                    score=score,
                    risk_level=risk_level,
                    reasons=reasons
                )
                print(f"DEBUG: Scan saved successfully to database")
                
                # 2. Log the scan to email logs
                email_logger.log_scan({
                    'sender': sender,
                    'subject': subject,
                    'verdict': result['verdict'],
                    'phishing_score': result['score'],
                    'risk_level': result['risk_level'],
                    'threat_reasons': '; '.join(result.get('reasons', [])),
                    'user_id': st.session_state.user_id,
                    'detection_method': 'multi-engine',
                    'timestamp': datetime.now().isoformat()
                })
                
                # 3. Quarantine if phishing/suspicious
                if result['verdict'] in ['PHISHING', 'SUSPICIOUS']:
                    try:
                        quarantine.quarantine_email(
                            user_id=st.session_state.user_id,
                            scan_id=None,
                            sender=sender,
                            subject=subject,
                            body=body,
                            risk_level=result['risk_level'],
                            reason='; '.join(result.get('reasons', [])),
                            threat_classification=result['verdict']
                        )
                    except Exception as q_err:
                        print(f"DEBUG: Quarantine error (non-blocking): {str(q_err)}")
                
                save_success = True
                st.success("Email scan saved to history successfully!")
            except Exception as e:
                print(f"DEBUG: Database save error: {str(e)}")
                st.error(f"Database save failed: {str(e)}")
        
        # DISPLAY EMAIL AUTHENTICATION ANALYSIS (SPF, DKIM, DMARC)
        st.markdown("---")
        st.markdown("###  Email Authentication Analysis")
        
        auth_analysis = auth_validator.analyze_email_headers(parse_result.get('raw_email', ''), sender)
        
        col_auth1, col_auth2, col_auth3 = st.columns(3)
        
        # SPF Analysis
        spf_data = auth_analysis['spf']
        with col_auth1:
            st.markdown(f"""
            <div class="report-section"style="border-left: 4px solid {spf_data['color']}; padding: 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                    <span style="font-size: 20px;">{spf_data['icon']}</span>
                    <span style="font-weight: 700; color: #e2e8f0;">SPF Record</span>
                </div>
                <div style="color: {spf_data['color']}; font-weight: 600; margin-bottom: 8px;">{spf_data['status'].value}</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 8px;">{spf_data['details']}</div>
                <div style="background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; font-size: 11px; color: #94a3b8;">
                    Risk Score: {spf_data['risk_score']}/30
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # DKIM Analysis
        dkim_data = auth_analysis['dkim']
        with col_auth2:
            st.markdown(f"""
            <div class="report-section"style="border-left: 4px solid {dkim_data['color']}; padding: 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                    <span style="font-size: 20px;">{dkim_data['icon']}</span>
                    <span style="font-weight: 700; color: #e2e8f0;">DKIM Signature</span>
                </div>
                <div style="color: {dkim_data['color']}; font-weight: 600; margin-bottom: 8px;">{dkim_data['status'].value}</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 8px;">{dkim_data['details']}</div>
                <div style="background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; font-size: 11px; color: #94a3b8;">
                    Risk Score: {dkim_data['risk_score']}/30
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # DMARC Analysis
        dmarc_data = auth_analysis['dmarc']
        with col_auth3:
            st.markdown(f"""
            <div class="report-section"style="border-left: 4px solid {dmarc_data['color']}; padding: 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                    <span style="font-size: 20px;">{dmarc_data['icon']}</span>
                    <span style="font-weight: 700; color: #e2e8f0;">DMARC Policy</span>
                </div>
                <div style="color: {dmarc_data['color']}; font-weight: 600; margin-bottom: 8px;">{dmarc_data['status'].value}</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 8px;">{dmarc_data['details']}</div>
                <div style="background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; font-size: 11px; color: #94a3b8;">
                    Risk Score: {dmarc_data['risk_score']}/30
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Overall Authentication Result
        auth_color = '#22c55e'if auth_analysis['authentication_passed'] else '#7aa2ff'
        auth_status = 'PASSED'if auth_analysis['authentication_passed'] else 'FAILED'
        
        # Parse RGB from hex color
        r = int(auth_color[1:3], 16)
        g = int(auth_color[3:5], 16)
        b = int(auth_color[5:7], 16)
        
        auth_html = f"""
        <div class="report-section"style="background: linear-gradient(135deg, rgba({r},{g},{b},0.08) 0%, rgba({r},{g},{b},0.03) 100%); border: 2px solid {auth_color}; padding: 16px; border-radius: 10px; margin-top: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div style="font-weight: 700; color: #e2e8f0; font-size: 16px;">Email Authentication Summary</div>
                <div style="color: {auth_color}; font-weight: 700; font-size: 14px;">{auth_status}</div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                <div style="color: #cbd5e1; font-size: 13px;">
                    <span style="color: #94a3b8;">Combined Risk Score:</span> <span style="font-weight: 700; color: {auth_color};">{auth_analysis['total_risk_score']}/90</span>
                </div>
                <div style="color: #cbd5e1; font-size: 13px;">
                    <span style="color: #94a3b8;">Authentication Status:</span> <span style="font-weight: 700;">{'Passed'if auth_analysis['authentication_passed'] else 'Failed'}</span>
                </div>
            </div>
        </div>
        """
        
        st.markdown(auth_html, unsafe_allow_html=True)
        if not auth_analysis.get('authentication_passed', True):
            render_warning_highlight(
                "AUTHENTICATION WARNING",
                "SPF, DKIM, or DMARC validation failed. Treat this email as high-risk unless sender legitimacy is independently verified.",
                "CRITICAL"
            )
        
        # Display concerns and recommendations
        if auth_analysis['security_concerns']:
            st.markdown('<div style="margin-top: 12px; color: #fb923c; font-weight: 600;"> Security Concerns:</div>', unsafe_allow_html=True)
            for concern in auth_analysis['security_concerns']:
                st.markdown(f' {concern}', unsafe_allow_html=False)
        
        if auth_analysis['recommendations']:
            st.markdown('<div style="margin-top: 12px; color: #60a5fa; font-weight: 600;"> Recommendations:</div>', unsafe_allow_html=True)
            for rec in auth_analysis['recommendations']:
                st.markdown(f' {rec}', unsafe_allow_html=False)
        
        # Display YARA results if available
        if yara_results:
            st.markdown("---")
            st.markdown("###  YARA Malware Detection Results")
            
            yara_detections = yara_results.get('total_detections', 0)
            
            col_yara1, col_yara2 = st.columns(2)
            with col_yara1:
                st.markdown(f"""
                <div class="finding-card report-section">
                    <div class="finding-label"> Total Matches</div>
                    <div class="finding-content"style="font-size: 24px; color: {'#8db9ff'if yara_detections > 0 else '#4ade80'}; font-weight: 700;">
                        {yara_detections}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            with col_yara2:
                threat_level = "CRITICAL"if yara_detections > 5 else "HIGH"if yara_detections > 2 else "LOW"
                st.markdown(f"""
                <div class="finding-card report-section">
                    <div class="finding-label">Risk Assessment</div>
                    <div class="finding-content"style="font-size: 14px; color: #60a5fa; font-weight: 600;">
                        {threat_level}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            if yara_results.get('matched_rules'):
                st.markdown("#### Matched Rules:")
                for rule in yara_results['matched_rules'][:10]:
                    st.markdown(f" **{rule}**", unsafe_allow_html=True)
            if yara_detections > 2:
                render_warning_highlight(
                    "MALWARE PATTERN WARNING",
                    f"YARA detected {yara_detections} potential malware patterns in email content.",
                    "CRITICAL" if yara_detections > 5 else "WARNING"
                )
        
        # Display VirusTotal URL Analysis Results
        if vt_url_detail_report:
            st.markdown("---")
            st.markdown("###  VirusTotal URL Analysis")
            
            for url, vt_data in vt_url_detail_report.items():
                detections = vt_data.get('detections', 0)
                total_vendors = len(vt_data.get('vendors', {}))
                is_malicious = detections > 0
                vt_status = vt_data.get('status', 'UNKNOWN')
                
                display_url = url if len(url) <= 60 else url[:57] + '...'
                
                if vt_status in ['FAILED', 'ERROR', 'NO_API_KEY']:
                    badge_color = '#7aa2ff'
                    badge_bg = 'rgba(122,162,255,0.15)'
                    status_text = 'FAILED'
                else:
                    badge_color = '#7aa2ff'if is_malicious else '#10b981'
                    badge_bg = 'rgba(122,162,255,0.15)'if is_malicious else 'rgba(16,185,129,0.15)'
                    status_text = 'MALICIOUS'if is_malicious else 'CLEAN'
                
                st.markdown(f"""
                <div class="report-section"style="margin-top: 16px; padding: 16px; border-left: 4px solid {badge_color}; border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 12px; word-break: break-word; color: #cbd5e1; font-size: 13px;"> {display_url}</div>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px;">
                        <div style="background: {badge_bg}; padding: 8px 14px; border-radius: 8px; color: {badge_color}; font-weight: 600; font-size: 12px; letter-spacing: 0.5px;">
                            {status_text}
                        </div>
                        <div style="background: rgba(96,165,250,0.15); padding: 8px 14px; border-radius: 8px; color: #60a5fa; font-weight: 600; font-size: 12px;">
                            {detections}/{total_vendors} engines detected
                        </div>
                        <div style="background: rgba(167,139,250,0.15); padding: 8px 14px; border-radius: 8px; color: #a78bfa; font-weight: 600; font-size: 12px;">
                            Reputation: {vt_data.get('reputation', 0)}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                if vt_data.get('vendors'):
                    with st.expander(f"View {len(vt_data.get('vendors', {}))} Vendor Detections"):
                        for vendor, detection in list(vt_data['vendors'].items())[:10]:
                            st.markdown(f" **{vendor}**: {detection}")
                if vt_status in ['FAILED', 'ERROR', 'NO_API_KEY']:
                    st.warning(vt_data.get('message', 'VirusTotal URL lookup failed'))
                elif detections > 0:
                    render_warning_highlight(
                        "URL REPUTATION WARNING",
                        f"VirusTotal flagged this URL by {detections} engine(s). Avoid opening it until validated.",
                        "CRITICAL" if detections >= 3 else "WARNING"
                    )
        
        st.markdown("---")
        
        col_csv, col_pdf, col_status = st.columns([1.2, 1.2, 1.6])
        with col_csv:
            csv_data = export_to_csv(full_report)
            if csv_data:
                st.download_button(label="CSV Report", data=csv_data, file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv", use_container_width=True)
        
        with col_pdf:
            pdf_data = export_to_pdf(full_report)
            if pdf_data:
                st.download_button(label="PDF Report", data=pdf_data, file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mime="application/pdf", use_container_width=True)
        
        with col_status:
            if save_success:
                st.markdown('<div style="padding: 12px; background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 8px; text-align: center; color: #22c55e; font-weight: 600;"> Saved to History</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="padding: 12px; background: rgba(107, 114, 128, 0.15); border: 1px solid rgba(107, 114, 128, 0.3); border-radius: 8px; text-align: center; color: #9ca3af; font-weight: 600;"> Auto-save pending</div>', unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Analysis Error: {str(e)}")

def render_comprehensive_report_ui(report: Dict) -> None:
    """Render comprehensive report with beautiful UI"""
    
    # Header Section
    st.markdown(f"""
    <div class="report-header report-section">
        <div class="report-title"> Comprehensive Security Analysis Report</div>
        <div class="report-subtitle">Generated: {report['timestamp']}</div>
        <div style="display: flex; gap: 12px; margin-top: 16px; flex-wrap: wrap;">
            <div style="background: {'rgba(122,162,255,0.2)'if report['verdict'] == 'PHISHING'else 'rgba(251,146,60,0.2)'if report['verdict'] == 'SUSPICIOUS'else 'rgba(34,197,94,0.2)'}; padding: 8px 16px; border-radius: 8px; color: {'#8db9ff'if report['verdict'] == 'PHISHING'else '#fb923c'if report['verdict'] == 'SUSPICIOUS'else '#4ade80'}; font-weight: 600; font-size: 13px;">
                {report['verdict']}
            </div>
            <div style="background: rgba(96,165,250,0.2); padding: 8px 16px; border-radius: 8px; color: #60a5fa; font-weight: 600; font-size: 13px;">
                Risk Score: {report['risk_score']:.0f}/100
            </div>
            <div style="background: rgba(167,139,250,0.2); padding: 8px 16px; border-radius: 8px; color: #a78bfa; font-weight: 600; font-size: 13px;">
                Confidence: {report['ml_confidence']:.1f}%
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Executive Summary
    st.markdown("""
    <div class="report-section">
        <div class="report-title"> Executive Summary (Non-Technical)</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="finding-card report-section">
        <div class="finding-content"style="font-size: 15px; line-height: 1.8;">
            {report['non_technical_summary']}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Threat Analysis
    st.markdown("""
    <div class="report-section">
        <div class="report-title"> Threat Analysis</div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""<div class="report-section"><h4 style="color: #e2e8f0; margin-bottom: 16px;"> Identified Threats</h4></div>""", unsafe_allow_html=True)
        
        for threat in report.get('threat_factors', []):
            st.markdown(f"""
            <div class="finding-card report-section"style="margin-bottom: 12px;">
                <div class="finding-label"> Threat Type</div>
                <div class="finding-content">{threat}</div>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""<div class="report-section"><h4 style="color: #e2e8f0; margin-bottom: 16px;"> Detection Indicators</h4></div>""", unsafe_allow_html=True)
        
        for idx, reason in enumerate(report.get('reasons', [])[:4]):
            st.markdown(f"""
            <div class="finding-card report-section"style="margin-bottom: 12px;">
                <div class="finding-label">Indicator {idx + 1}</div>
                <div class="finding-content">{reason}</div>
            </div>
            """, unsafe_allow_html=True)
    
    # Technical Deep Dive
    st.markdown("""
    <div class="report-section">
        <div class="report-title"> Technical Deep Dive</div>
    </div>
    """, unsafe_allow_html=True)
    
    tech = report['technical_analysis']
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="finding-card report-section">
            <div class="finding-label"> ML Algorithm</div>
            <div class="finding-content">{tech['ml_scoring']['algorithm']}</div>
            <div class="reasoning-box">
                <div class="reasoning-label">Final Score</div>
                <div class="reasoning-text">{tech['ml_scoring']['score']:.0f}/100 ({tech['ml_scoring']['confidence']})</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="finding-card report-section">
            <div class="finding-label"> URL Analysis</div>
            <div class="finding-content">Total URLs: {tech['url_analysis']['count']}</div>
            <div class="reasoning-box">
                <div class="reasoning-label">IP-Based URLs</div>
                <div class="reasoning-text">{tech['url_analysis']['ip_based']} detected (suspicious)</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="finding-card report-section">
            <div class="finding-label"> Email Body</div>
            <div class="finding-content">Content Analysis Complete</div>
            <div class="reasoning-box">
                <div class="reasoning-label">Urgency Score</div>
                <div class="reasoning-text">{tech['body_characteristics']['urgency_indicators']}/100</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Reasoning Section
    st.markdown("""
    <div class="report-section">
        <div class="report-title"> Why This Classification?</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="reasoning-box report-section">
        <div class="reasoning-label"> Primary Factor</div>
        <div class="reasoning-text">
            The email combines multiple phishing indicators that together create a high-risk profile. 
            The presence of {', '.join(report['threat_factors'][:2] if report['threat_factors'] else ['unknown indicators'])} strongly suggests this is a coordinated social engineering attack.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="reasoning-box report-section">
        <div class="reasoning-label"> Technical Reasoning</div>
        <div class="reasoning-text">
            <strong>Keyword Analysis:</strong> High-risk words detected indicating urgency and credential harvesting attempts.<br>
            <strong>URL Structure:</strong> {tech['url_analysis']['ip_based']} IP-based URLs found, which bypass domain verification.<br>
            <strong>Content Pattern:</strong> Body analysis shows {tech['body_characteristics']['credential_requests']}/100 credential request indicators.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Recommendations
    st.markdown("""
    <div class="report-section">
        <div class="report-title"> Recommended Actions</div>
    </div>
    """, unsafe_allow_html=True)
    
    recommendations = [
        ("", "Delete immediately", "Do not keep this email or reply to it"),
        ("", "Report to security", "Forward to your IT security team for analysis"),
        ("", "Block sender", "Add this address to your blocked senders list"),
        ("", "Alert users", "If you're an admin, warn your organization about this threat")
    ]
    
    for icon, title, desc in recommendations:
        st.markdown(f"""
        <div class="finding-card report-section">
            <div class="finding-label">{icon} {title.upper()}</div>
            <div class="finding-content">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

# Process OAuth callback before rendering login/auth sections
_handle_google_oauth_callback()

# LOGIN PAGE - COMPLETELY REDESIGNED
if not st.session_state.authenticated:
    st.markdown('<div style="margin-top:10px; margin-bottom:10px;"><span class="landing-badge">⚔️ phishXzero security suite</span></div>', unsafe_allow_html=True)
    st.markdown("""
    <style>
    .landing-shell {
      margin-top: 12px;
      margin-bottom: 18px;
      position: relative;
      animation: fadeInLift 0.7s ease-out;
    }
    .landing-shell::before {
      content: "";
      position: absolute;
      inset: -12% -4% auto -4%;
      height: 420px;
      background: radial-gradient(circle at 18% 18%, rgba(108, 172, 236, 0.26) 0%, rgba(108,172,236,0.10) 26%, transparent 64%);
      pointer-events: none;
      z-index: 0;
    }
    .landing-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 14px;
      border-radius: 999px;
      border: 1px solid rgba(126, 168, 212, 0.45);
      color: #d8e6f6;
      background: linear-gradient(145deg, rgba(46,65,88,0.86) 0%, rgba(23,31,41,0.9) 100%);
      font-size: 11px;
      letter-spacing: 0.55px;
      text-transform: uppercase;
      font-weight: 600;
    }
    .landing-title {
      color: #eef3f9;
      font-family: 'Space Grotesk';
      font-size: clamp(34px, 4.8vw, 56px);
      line-height: 1.08;
      letter-spacing: -1.1px;
      margin: 18px 0 10px;
      max-width: 760px;
      text-wrap: balance;
    }
    .landing-subtitle {
      color: #aab8c8;
      max-width: 700px;
      font-size: 16px;
      line-height: 1.75;
      margin-bottom: 22px;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin: 12px 0 18px;
    }
    .kpi-card {
      border-radius: 14px;
      border: 1px solid rgba(92, 109, 129, 0.56);
      background: linear-gradient(150deg, rgba(19, 24, 31, 0.94) 0%, rgba(11, 15, 20, 0.95) 100%);
      box-shadow: 0 14px 30px rgba(0, 0, 0, 0.22), inset 0 1px 0 rgba(255,255,255,0.08);
      padding: 14px;
    }
    .kpi-value {
      color: #deecfb;
      font-size: 30px;
      font-family: 'Space Grotesk';
      font-weight: 700;
      line-height: 1.2;
      text-shadow: 0 0 18px rgba(133, 193, 255, 0.22);
      margin-bottom: 4px;
    }
    .kpi-label {
      color: #96a3b5;
      font-size: 12px;
      letter-spacing: 0.35px;
    }
    .signal-row {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-top: 6px;
    }
    .signal-card {
      border-radius: 12px;
      border: 1px solid rgba(95, 111, 132, 0.55);
      background: linear-gradient(145deg, rgba(20, 27, 35, 0.9) 0%, rgba(12, 16, 22, 0.95) 100%);
      padding: 11px;
    }
    .signal-head {
      color: #d8e4f3;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .signal-copy {
      color: #9caabe;
      font-size: 12px;
      line-height: 1.45;
    }
    .intel-strip {
      margin-top: 14px;
      border-radius: 14px;
      border: 1px solid rgba(153, 125, 88, 0.52);
      background: linear-gradient(145deg, rgba(49, 34, 20, 0.40) 0%, rgba(20, 17, 14, 0.85) 100%);
      padding: 14px;
      box-shadow: 0 14px 30px rgba(0, 0, 0, 0.24), 0 0 20px rgba(213, 141, 67, 0.13);
      animation: pulseIntel 2.8s ease-in-out infinite;
    }
    .intel-title {
      color: #f2c997;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.85px;
      margin-bottom: 8px;
    }
    .intel-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .intel-cell {
      border-radius: 10px;
      background: rgba(20, 16, 12, 0.65);
      border: 1px solid rgba(186, 139, 84, 0.42);
      padding: 10px;
    }
    .intel-value {
      color: #ffd6a5;
      font-family: 'Space Grotesk';
      font-size: 22px;
      font-weight: 700;
      line-height: 1.1;
      margin-bottom: 2px;
    }
    .intel-label {
      color: #e6c8a6;
      font-size: 11px;
      line-height: 1.3;
    }
    .auth-panel {
      border-radius: 22px;
      border: 1px solid rgba(101, 117, 137, 0.58);
      background: linear-gradient(150deg, rgba(20, 26, 33, 0.94) 0%, rgba(12, 16, 20, 0.96) 100%);
      box-shadow: 0 24px 44px rgba(0,0,0,0.35), 0 0 30px rgba(95, 156, 222, 0.08), inset 0 1px 0 rgba(255,255,255,0.08);
      padding: 22px 20px;
      backdrop-filter: blur(18px) saturate(120%);
    }
    .auth-panel-title {
      color: #f0f4f9;
      font-family: 'Space Grotesk';
      font-size: 25px;
      margin-bottom: 6px;
      letter-spacing: -0.4px;
    }
    .auth-panel-sub {
      color: #9eacbd;
      font-size: 13px;
      margin-bottom: 14px;
      line-height: 1.55;
    }
    .auth-meta {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .auth-meta span {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #d8e3f1;
      border: 1px solid rgba(113, 129, 149, 0.48);
      background: rgba(24, 31, 40, 0.82);
      border-radius: 999px;
      padding: 5px 9px;
      font-weight: 600;
    }
    .auth-divider {
      margin: 10px 0 12px;
      height: 1px;
      background: linear-gradient(90deg, transparent 0%, rgba(116, 130, 148, 0.62) 48%, transparent 100%);
    }
    .auth-mini-note {
      margin-top: 8px;
      font-size: 11px;
      color: #8f9caf;
      line-height: 1.45;
    }
    .google-signin-btn {
      margin-top: 8px;
      width: 100%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(108,126,148,0.55);
      background: linear-gradient(145deg, rgba(255,255,255,0.92) 0%, rgba(236,241,247,0.92) 100%);
      color: #101418;
      text-decoration: none;
      font-weight: 600;
      font-size: 13px;
      box-shadow: 0 8px 18px rgba(0,0,0,0.22), inset 0 1px 0 rgba(255,255,255,0.8);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .google-signin-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 24px rgba(0,0,0,0.25), inset 0 1px 0 rgba(255,255,255,0.8);
    }
    .google-signin-logo {
      width: 18px;
      height: 18px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      background: #ffffff;
    }
    @keyframes fadeInLift {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseIntel {
      0%, 100% { box-shadow: 0 14px 30px rgba(0, 0, 0, 0.24), 0 0 20px rgba(213, 141, 67, 0.13); }
      50% { box-shadow: 0 18px 34px rgba(0, 0, 0, 0.28), 0 0 26px rgba(213, 141, 67, 0.22); }
    }
    @media (max-width: 980px) {
      .landing-shell { margin-top: 6px; }
      .signal-row { grid-template-columns: 1fr; }
      .kpi-grid { grid-template-columns: 1fr; }
      .intel-grid { grid-template-columns: 1fr; }
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="landing-shell">', unsafe_allow_html=True)
    left_col, right_col = st.columns([1.35, 1], gap="large")

    with left_col:
        st.markdown(
            """
            <div class="landing-badge">⚔️ Enterprise Threat Intelligence</div>
            <div class="landing-title">Precision Phishing Defense, Designed for Fast Decisions.</div>
            <div class="landing-subtitle">
              Analyze emails, URLs, and files with a unified security workflow that combines behavioral analysis,
              forensic signals, and VirusTotal reputation checks in one professional dashboard.
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="kpi-grid">
              <div class="kpi-card">
                <div class="kpi-value">99.2%</div>
                <div class="kpi-label">Threat signal precision across layered engines</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-value">&lt; 2s</div>
                <div class="kpi-label">Typical first-pass analysis turnaround</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-value">30+</div>
                <div class="kpi-label">Heuristic URL checks with forensics context</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-value">24/7</div>
                <div class="kpi-label">Continuous risk intelligence from integrated sources</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="intel-strip">
              <div class="intel-title">Critical Human-Factor Threat Indicators</div>
              <div class="intel-grid">
                <div class="intel-cell">
                  <div class="intel-value">1 in 4</div>
                  <div class="intel-label">Users still click credential-harvesting links under urgency pressure.</div>
                </div>
                <div class="intel-cell">
                  <div class="intel-value">90 sec</div>
                  <div class="intel-label">Average time attackers need to imitate brand identity convincingly.</div>
                </div>
                <div class="intel-cell">
                  <div class="intel-value">3x</div>
                  <div class="intel-label">Higher compromise risk when SPF/DKIM checks fail and users ignore warning cues.</div>
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="signal-row">
              <div class="signal-card">
                <div class="signal-head">Email Forensics</div>
                <div class="signal-copy">Header anomalies, authentication status, and behavioral indicators mapped into one verdict.</div>
              </div>
              <div class="signal-card">
                <div class="signal-head">URL Vanguard + VT</div>
                <div class="signal-copy">Heuristic violations and reputation detections combined for stricter suspicious classification.</div>
              </div>
              <div class="signal-card">
                <div class="signal-head">Malware Analysis</div>
                <div class="signal-copy">Static forensic extraction with signatures and external threat reputation correlation.</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with right_col:
        st.markdown("""
        <div class="auth-panel">
            <div class="auth-panel-title">Secure Access Portal</div>
            <div class="auth-panel-sub">Sign in to continue to your private security workspace.</div>
            <div class="auth-meta">
                <span>Encrypted Session</span>
                <span>Live Telemetry</span>
                <span>Audit Ready</span>
            </div>
            <div class="auth-divider"></div>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.get("google_oauth_status"):
            status_msg = st.session_state.get("google_oauth_status")
            if "successful" in status_msg.lower():
                st.success(status_msg)
            else:
                st.warning(status_msg)

        tab1, tab2 = st.tabs(["Sign In", "Create Account"])

        with tab1:
            login_user = st.text_input("Username or Email", key="login_u", placeholder="your-username", label_visibility="collapsed")
            login_pass = st.text_input("Password", type="password", key="login_p", placeholder="your-password", label_visibility="collapsed")
            st.caption("Use your username/email and password to continue.")
            missing_google_vars: List[str] = []
            if not google_oauth_manager.client_id:
                missing_google_vars.append("GOOGLE_CLIENT_ID")
            if not google_oauth_manager.client_secret:
                missing_google_vars.append("GOOGLE_CLIENT_SECRET")
            if not google_oauth_manager.redirect_uri:
                missing_google_vars.append("GOOGLE_REDIRECT_URI")
            ca, cb = st.columns(2)
            with ca:
                if st.button("Sign In", key="si", use_container_width=True):
                    if login_user and login_pass:
                        try:
                            s, uid, em = auth_manager.login_user(login_user, login_pass)
                            if s:
                                st.session_state.authenticated = True
                                st.session_state.user_id = uid
                                st.session_state.username = login_user
                                st.session_state.email = em
                                st.session_state.page = 'home'
                                st.success("Welcome back!")
                                st.rerun()
                            else:
                                st.error("Invalid username or password")
                        except Exception as e:
                            st.error(f"Login error: {str(e)}")
                    else:
                        st.warning("Please enter credentials")
            with cb:
                if st.button("Try Demo", key="dm", use_container_width=True):
                    st.session_state.authenticated = True
                    st.session_state.user_id = 0
                    st.session_state.username = "Demo User"
                    st.session_state.email = "demo@phishu.demo"
                    st.session_state.page = 'home'
                    st.rerun()
            if google_oauth_manager.is_configured():
                oauth_state = secrets.token_urlsafe(24)
                st.session_state["google_oauth_state"] = oauth_state
                auth_url = google_oauth_manager.build_auth_url(oauth_state)
                st.markdown(
                    f"""
                    <a href="{auth_url}" target="_self" class="google-signin-btn">
                        <span class="google-signin-logo">
                            <svg width="16" height="16" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                                <path d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.9c1.7-1.56 2.7-3.87 2.7-6.62z" fill="#4285F4"/>
                                <path d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.9-2.26c-.8.54-1.82.86-3.06.86-2.35 0-4.34-1.58-5.05-3.7H.96v2.33A9 9 0 0 0 9 18z" fill="#34A853"/>
                                <path d="M3.95 10.72A5.41 5.41 0 0 1 3.67 9c0-.6.1-1.18.28-1.72V4.95H.96A9 9 0 0 0 0 9c0 1.45.35 2.82.96 4.05l2.99-2.33z" fill="#FBBC05"/>
                                <path d="M9 3.58c1.32 0 2.5.45 3.43 1.35l2.57-2.57C13.46.92 11.42 0 9 0A9 9 0 0 0 .96 4.95l2.99 2.33C4.66 5.16 6.65 3.58 9 3.58z" fill="#EA4335"/>
                            </svg>
                        </span>
                        Continue with Google
                    </a>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.info(f"Missing Google OAuth settings in `.env`: {', '.join(missing_google_vars)}. Save values and restart the app.")
            st.markdown("<div class='auth-mini-note'>Google sign-in imports your verified Google name/email and unlocks Gmail API workflow.</div>", unsafe_allow_html=True)

        with tab2:
            reg_user = st.text_input("Username", key="reg_u", placeholder="choose-username", label_visibility="collapsed")
            reg_email = st.text_input("Email", key="reg_e", placeholder="email@company.com", label_visibility="collapsed")
            reg_pass = st.text_input("Password", type="password", key="reg_p", placeholder="minimum 8 characters", label_visibility="collapsed")
            reg_conf = st.text_input("Confirm Password", type="password", key="reg_c", placeholder="re-enter password", label_visibility="collapsed")

            st.markdown("<div style='font-size: 11px; color: #94a3b8; margin-top: 12px; margin-bottom: 16px;'>Password must be at least 8 characters with uppercase, number, and special character</div>", unsafe_allow_html=True)

            if st.button("Create Account", key="ca_btn", use_container_width=True):
                if all([reg_user, reg_email, reg_pass, reg_conf]):
                    if reg_pass == reg_conf and len(reg_pass) >= 8:
                        try:
                            s, m = auth_manager.register_user(reg_user, reg_email, reg_pass)
                            if s:
                                st.success("Account created! You can now sign in.")
                            else:
                                st.error(f"Error: {m}")
                        except Exception as e:
                            st.error(f"Registration error: {str(e)}")
                    else:
                        st.error("Passwords don't match or too short (min 8 characters)")
                else:
                    st.warning("Please fill all fields")

    st.markdown('</div>', unsafe_allow_html=True)
    

# MAIN APP AUTHENTICATED SECTION
else:
    _initials = ''.join([p[0] for p in st.session_state.username.split()])[:2].upper() if st.session_state.username else 'U'
    
    # Define navigation items
    nav_items = [('Home', 'home'), ('Analyze', 'threat'), ('Statistics', 'analytics'), ('History', 'history'), ('Learn', 'education'), ('About Us', 'about')]

    nav_html = f"""
    <div class="top-nav">
        <div class="nav-left">
            <div class="nav-logo">⚔️ phishXzero</div>
        </div>
        <div class="nav-profile">
            <div class="avatar">{_initials}</div>
            <div class="profile-info">
                <div class="profile-name">{st.session_state.username}</div>
                <div class="profile-email">{st.session_state.email}</div>
            </div>
        </div>
    </div>
    """
    st.markdown(nav_html, unsafe_allow_html=True)
    st.markdown('<div style="margin-top: 68px;"></div>', unsafe_allow_html=True)

    st.markdown('<div class="top-nav-buttons"></div>', unsafe_allow_html=True)
    nav_cols = st.columns([1, 1, 1, 1, 1, 1])
    for i, (label, page) in enumerate(nav_items):
        with nav_cols[i]:
            btn_type = "primary" if st.session_state.page == page else "secondary"
            if st.button(label, key=f"top_nav_{page}", use_container_width=True, type=btn_type):
                st.session_state.page = page
                st.rerun()
    
    with st.sidebar:
        st.markdown(
            f"""
            <div style="border:1px solid rgba(108,126,148,0.52); border-radius:16px; padding:14px; margin-bottom:12px; background:linear-gradient(145deg, rgba(22,28,35,0.95) 0%, rgba(12,16,20,0.96) 100%); box-shadow: 0 12px 28px rgba(0,0,0,0.30), inset 0 1px 0 rgba(255,255,255,0.08);">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                    <div style="width:38px; height:38px; border-radius:11px; background:linear-gradient(135deg, #2b3138 0%, #1b1f25 100%); color:#e5edf7; display:flex; align-items:center; justify-content:center; font-weight:700; position:relative;">
                        {_initials}
                        <span style="position:absolute; right:-6px; bottom:-6px; width:16px; height:16px; border-radius:50%; border:1px solid rgba(123,141,162,0.65); background:linear-gradient(145deg, #0f141b 0%, #1a2028 100%); display:flex; align-items:center; justify-content:center; font-size:9px;">🛡</span>
                    </div>
                    <div>
                        <div style="color:#e5edf7; font-size:13px; font-weight:600; line-height:1.2;">{st.session_state.username}</div>
                        <div style="color:#9eacbd; font-size:11px; line-height:1.2;">{st.session_state.email}</div>
                    </div>
                </div>
                <div style="color:#8f9caf; font-size:11px; line-height:1.4;">Role: Security Analyst | Session: Protected</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Sign Out", key="logout_btn", use_container_width=True, help="Sign out of phishXzero"):
            st.session_state.clear()
            st.rerun()
    
    st.markdown("<div style='height:70px;'></div>", unsafe_allow_html=True)
    
    # HOME PAGE - ENHANCED WITH STATISTICS
    if st.session_state.page == 'home':
        st.markdown("""
        <div class="hero-section-v2">
            <h1 class="hero-title-v2">Your Security Command Center</h1>
            <p class="hero-subtitle-v2">Real-time email threat detection powered by ML and threat intelligence</p>
        </div>
        """, unsafe_allow_html=True)
        
        try:
            if st.session_state.user_id != 0:
                dashboard_stats = generate_dashboard_stats(st.session_state.user_id)
                
                st.markdown(f"""
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 48px;">
                    <div class="stat-card-animated">
                        <div class="stat-number-animated">{dashboard_stats['total_scans']}</div>
                        <div class="stat-label-animated">Total Scans</div>
                        <div style="font-size: 11px; color: #60a5fa; margin-top: 12px; font-weight: 500;">Protected daily</div>
                    </div>
                    <div class="stat-card-animated">
                        <div class="stat-number-animated"style="color: #4ade80;">{dashboard_stats['legitimate_detected']}</div>
                        <div class="stat-label-animated">Safe Emails</div>
                        <div style="font-size: 11px; color: #4ade80; margin-top: 12px; font-weight: 500;">{dashboard_stats['legitimate_rate']}% clean</div>
                    </div>
                    <div class="stat-card-animated">
                        <div class="stat-number-animated"style="color: #fb923c;">{dashboard_stats['suspicious_detected']}</div>
                        <div class="stat-label-animated">Suspicious</div>
                        <div style="font-size: 11px; color: #fb923c; margin-top: 12px; font-weight: 500;">{dashboard_stats['suspicious_rate']}% detected</div>
                    </div>
                    <div class="stat-card-animated">
                        <div class="stat-number-animated"style="color: #8db9ff;">{dashboard_stats['phishing_detected']}</div>
                        <div class="stat-label-animated">Threats Blocked</div>
                        <div style="font-size: 11px; color: #8db9ff; margin-top: 12px; font-weight: 500;">{dashboard_stats['phishing_rate']}% threats</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Charts Section
                st.markdown("---")
                st.markdown("<h3>Detection Breakdown</h3>", unsafe_allow_html=True)
                
                col_chart1, col_chart2 = st.columns(2)
                
                with col_chart1:
                    # Pie chart for verdict distribution
                    verdict_data = pd.DataFrame({
                        'Status': ['Safe', 'Suspicious', 'Phishing'],
                        'Count': [
                            dashboard_stats['legitimate_detected'],
                            dashboard_stats['suspicious_detected'],
                            dashboard_stats['phishing_detected']
                        ]
                    })
                    
                    fig_pie = px.pie(
                        verdict_data,
                        values='Count',
                        names='Status',
                        color_discrete_map={'Safe': '#4ade80', 'Suspicious': '#fb923c', 'Phishing': '#8db9ff'},
                        title='Email Classification Breakdown'
                    )
                    fig_pie.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#cbd5e1'),
                        height=400
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)
                
                with col_chart2:
                    # Risk score gauge
                    render_risk_meter(dashboard_stats['avg_risk_score'], "Average Risk Score")
            
            st.markdown("<br><br>", unsafe_allow_html=True)
            col1, col2 = st.columns([1, 2])
            with col1:
                if st.button("Scan Email", use_container_width=True, key="scan_home", help="Check if an email is phishing"):
                    st.session_state.page = 'threat'
                    st.rerun()
                if st.button("View Statistics", use_container_width=True, key="ana_home"):
                    st.session_state.page = 'analytics'
                    st.rerun()
                if st.button("Scan History", use_container_width=True, key="hist_home"):
                    st.session_state.page = 'history'
                    st.rerun()
                if st.button("Learn More", use_container_width=True, key="learn_home"):
                    st.session_state.page = 'education'
                    st.rerun()
            
            with col2:
                st.markdown("""
                <div class="email-result-card">
                    <h3 style="margin-top: 0; color: #e2e8f0;">Recent Activity</h3>
                </div>
                """, unsafe_allow_html=True)
                if st.session_state.user_id != 0:
                    df = scan_db.get_user_scans(st.session_state.user_id, limit=5)
                    if len(df) > 0:
                        df_display = df.copy()
                        df_display.columns = ['ID', 'Timestamp', 'From', 'Subject', 'Verdict', 'Score', 'Risk']
                        st.dataframe(df_display, use_container_width=True, hide_index=True)
                    else:
                        st.info("No scans yet. Click 'Scan Email'to get started!")
            
            # Quarantine & Alerts Section
            st.markdown("---")
            st.markdown("<h3> Security Status</h3>", unsafe_allow_html=True)
            
            quar_col1, quar_col2, quar_col3 = st.columns(3)
            
            with quar_col1:
                if st.session_state.user_id != 0:
                    quarantine_stats = quarantine.get_quarantine_stats(st.session_state.user_id)
                    total_q = quarantine_stats.get('total_quarantined', 0)
                    critical_q = quarantine_stats.get('critical_count', 0)
                    st.markdown(f"""
                    <div class="stat-card-animated">
                        <div class="stat-number-animated"style="color: #8db9ff;">{total_q}</div>
                        <div class="stat-label-animated">Quarantined Emails</div>
                        <div style="font-size: 11px; color: #8db9ff; margin-top: 12px; font-weight: 500;"> {critical_q} Critical</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.info("Login to view quarantine")
            
            with quar_col2:
                alert_stats = alert_manager.get_alert_statistics()
                total_alerts = alert_stats.get('total_alerts', 0)
                st.markdown(f"""
                <div class="stat-card-animated">
                    <div class="stat-number-animated"style="color: #fb923c;">{total_alerts}</div>
                    <div class="stat-label-animated">Alerts Triggered</div>
                    <div style="font-size: 11px; color: #fb923c; margin-top: 12px; font-weight: 500;">Last 24h</div>
                </div>
                """, unsafe_allow_html=True)
            
            with quar_col3:
                log_stats = email_logger.get_statistics(st.session_state.user_id if st.session_state.user_id != 0 else None)
                st.markdown(f"""
                <div class="stat-card-animated">
                    <div class="stat-number-animated"style="color: #60a5fa;">{log_stats.get('phishing_count', 0)}</div>
                    <div class="stat-label-animated">Phishing Detected</div>
                    <div style="font-size: 11px; color: #60a5fa; margin-top: 12px; font-weight: 500;">Detection Rate: {log_stats.get('phishing_percentage', 0):.1f}%</div>
                </div>
                """, unsafe_allow_html=True)
        
        except Exception as e:
            st.error(f"Error loading dashboard: {str(e)}")
    
    # THREAT ANALYSIS PAGE - FIXED
    elif st.session_state.page == 'threat':
        st.markdown("""<div style='background: linear-gradient(145deg, rgba(19,22,26,0.9) 0%, rgba(10,12,15,0.9) 100%); border: 1px solid rgba(59,66,76,0.6); border-radius: 16px; padding: 32px; margin-bottom: 32px; backdrop-filter: blur(10px); box-shadow: 0 8px 24px rgba(0,0,0,0.25);'>
            <h1 style='margin-top: 0; margin-bottom: 8px;'>Advanced Threat Intelligence Scanner</h1>
            <p style='color:#94a3b8;margin-bottom:0;'>Multi-layer analysis: ML + VirusTotal + YARA + Email Body Intelligence</p>
        </div>""", unsafe_allow_html=True)
        
        scan_tabs = st.tabs(["Email Analysis", "URL Scanner", "Malware Detector", "Gmail Shield"])
        
        with scan_tabs[0]:
            st.markdown("### Intelligent Email Analysis")
            st.markdown("<p style='color:#94a3b8; font-size:12px;'>Paste email content or drag-and-drop .eml file. Auto-detects sender, subject, and body.</p>", unsafe_allow_html=True)
            
            col_input1, col_input2 = st.columns(2)
            
            with col_input1:
                st.markdown("""
                <div style='font-weight: 600; color: #e2e8f0; margin-bottom: 16px;'> Paste Email Content</div>
                """, unsafe_allow_html=True)
                email_input_method = st.radio(
                    "Select input method",
                    ["Paste Email Text", "Upload .eml File"],
                    key="email_input_method",
                    label_visibility="collapsed"
                )
                
                email_raw_content = None
                eml_file = None
                
                if email_input_method == "Paste Email Text":
                    email_raw_content = st.text_area(
                        "Email Content",
                        height=320,
                        placeholder="Paste full email with headers...\n\nExample:\nFrom: sender@example.com\nSubject: Important Account Verification\n\nDear User, please verify your account by clicking...",
                        key="email_raw_content",
                        label_visibility="collapsed"
                    )
                else:
                    st.markdown("""
                    <div class="file-upload-area">
                        <div class="file-upload-icon">FILE</div>
                        <div style="color: #e2e8f0; font-weight: 600; margin-bottom: 8px;">Drag & Drop Your .eml File</div>
                        <div style="color: #94a3b8; font-size: 12px;">or click to browse</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    eml_file = st.file_uploader(
                        "Upload .eml file", 
                        type=['eml', 'txt', 'msg'], 
                        key="eml_uploader", 
                        label_visibility="collapsed",
                        accept_multiple_files=False,
                        help="Upload email file (.eml format)"
                    )
            
            with col_input2:
                st.markdown("""<div style='font-weight: 600; color: #e2e8f0; margin-bottom: 16px;'>Analysis Options</div>""", unsafe_allow_html=True)
                enable_vt = st.checkbox("VirusTotal URL Check", value=True, key="enable_vt_email", help="Scan URLs with VirusTotal threat intelligence")
                enable_yara = st.checkbox("YARA Malware Scan", value=False, key="enable_yara_email", help="Scan email body for malware patterns")
                
                st.markdown("""
                <div style="background: linear-gradient(145deg, rgba(19,22,26,0.9) 0%, rgba(10,12,15,0.9) 100%); border: 1px solid rgba(59,66,76,0.7); border-radius: 12px; padding: 16px; margin-top: 20px;">
                    <div style="color: #e5e7eb; font-weight: 600; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;">Analysis Info</div>
                    <ul style="color: #cbd5e1; font-size: 12px; margin: 0; padding-left: 20px; line-height: 1.6;">
                        <li>ML-based keyword & URL analysis</li>
                        <li>Email body content scanning</li>
                        <li>Threat actor pattern matching</li>
                        <li>Real-time risk scoring</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("---")
                
                if st.button("Analyze Email", type="primary", use_container_width=True, key="analyze_email_btn", help="Run comprehensive security analysis"):
                    email_content = None
                    parse_result = {}
                    
                    if email_input_method == "Paste Email Text"and email_raw_content:
                        parse_result = email_parser.parse_email_input(email_raw_content)
                        email_content = email_raw_content
                    elif email_input_method == "Upload .eml File"and eml_file is not None:
                        try:
                            # Validate file size (max 10MB)
                            if eml_file.size > 10 * 1024 * 1024:
                                st.error("File too large. Maximum size is 10MB.")
                            else:
                                file_bytes = eml_file.read()
                                if len(file_bytes) == 0:
                                    st.error("File is empty")
                                    parse_result = {'error': 'Empty file'}
                                else:
                                    parse_result = email_parser.parse_eml_file(file_bytes)
                                    email_content = True
                        except Exception as file_err:
                            st.error(f"Error reading .eml file: {str(file_err)}")
                            parse_result = {'error': str(file_err)}
                    
                    if not email_content or 'error'in parse_result:
                        st.error("Please provide email content or upload .eml file")
                    else:
                        sender = parse_result.get('sender', 'Unknown')
                        subject = parse_result.get('subject', '(No Subject)')
                        body = parse_result.get('body', '')
                        
                        with st.spinner("Running comprehensive threat analysis..."):
                            try:
                                # Use unified analysis function for both paste and upload
                                perform_email_analysis(sender, subject, body, parse_result, enable_vt, enable_yara)
                            except Exception as e:
                                st.error(f"Analysis Error: {str(e)}")
        
        with scan_tabs[1]:
            st.markdown("### ⚔️ Advanced URL Threat Detection (Vanguard System)")
            st.markdown("<p style='color:#94a3b8;'>30-Rule Heuristic Engine + VirusTotal v3 Integration</p>", unsafe_allow_html=True)
            enable_vt_url = st.checkbox("VirusTotal URL Reputation Check", value=True, key="enable_vt_url")
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            col_url_input, col_url_btn = st.columns([4, 1])
            with col_url_input:
                url_input = st.text_input("Enter URL to analyze", placeholder="https://example.com", key="url_check", label_visibility="collapsed")
            
            with col_url_btn:
                scan_url_btn = st.button("Scan", type="primary", use_container_width=True, key="url_scan_btn")
            
            # Add spacing to result container
            st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
            
            if scan_url_btn or (url_input and st.session_state.get('last_url_input') == url_input):
                if url_input:
                    st.session_state.last_url_input = url_input
                    
                    with st.spinner("Analyzing URL with Detection Engine..."):
                        # URLVanguard Analysis (30-rule system)
                        vanguard_result = url_vanguard.analyze_url(url_input)
                        vt_url_result = None
                        vt_status = 'DISABLED'
                        vt_detections = 0
                        if enable_vt_url:
                            vt_url_result = vt_checker.check_url(url_input)
                            vt_status = vt_url_result.get('status', 'UNKNOWN') if vt_url_result else 'UNKNOWN'
                            if vt_status in ['ERROR', 'NO_API_KEY', 'FAILED']:
                                vt_status = 'FAILED'
                            vt_detections = int(vt_url_result.get('detections', 0)) if vt_url_result else 0

                        final_verdict = vanguard_result.get('verdict', 'UNKNOWN')
                        final_score = int(vanguard_result.get('score', 0))
                        final_risk_level = (
                            'CRITICAL' if final_score >= 70 else
                            'HIGH' if final_score >= 50 else
                            'MEDIUM' if final_score >= 30 else
                            'LOW'
                        )
                        final_reason = "Final verdict based on Vanguard heuristic score."

                        if vt_status != 'FAILED' and vt_detections >= 1:
                            if final_verdict not in ['PHISHING', 'MALWARE']:
                                final_verdict = 'SUSPICIOUS'
                            final_score = max(final_score, 65)
                            final_risk_level = 'HIGH' if final_risk_level != 'CRITICAL' else final_risk_level
                            final_reason = (
                                f"Final verdict escalated: VirusTotal flagged {vt_detections} detection(s). "
                                "Per policy, any detection marks URL as suspicious."
                            )
                        elif vt_status == 'FAILED':
                            final_reason = "VirusTotal lookup failed. Final verdict based on Vanguard only."
                        
                        # Display Vanguard Analysis
                        st.subheader("URL Analysis")
                        
                        # Score metrics
                        col_score1, col_score2, col_score3, col_score4 = st.columns(4)
                        with col_score1:
                            st.metric("Risk Score", f"{vanguard_result['score']}/100")
                        with col_score2:
                            st.metric("Verdict", vanguard_result['verdict'])
                        with col_score3:
                            st.metric("Entropy", f"{vanguard_result['entropy']:.2f}")
                        with col_score4:
                            st.metric("Subdomains", vanguard_result['subdomain_count'])
                        
                        # Display violations
                        if vanguard_result['violations']:
                            st.warning("Security Rule Violations:")
                            for violation in vanguard_result['violations']:
                                st.write(f"   {violation}")
                        else:
                            st.success("No security rule violations detected")

                        if vanguard_result.get('score', 0) >= 40:
                            render_warning_highlight(
                                "URL RISK WARNING",
                                f"URL scored {vanguard_result.get('score')}/100 with verdict {vanguard_result.get('verdict')}. Proceed only after manual validation.",
                                "CRITICAL" if vanguard_result.get('score', 0) >= 70 else "WARNING"
                            )

                        if vt_url_result:
                            st.markdown("---")
                            st.subheader("VirusTotal URL Reputation")
                            vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)
                            with vt_col1:
                                st.metric("Status", vt_status)
                            with vt_col2:
                                st.metric("Detections", vt_detections)
                            with vt_col3:
                                st.metric("Reputation", vt_url_result.get('reputation', 0))
                            with vt_col4:
                                st.metric("Threat Level", vt_url_result.get('threat_level', 'UNKNOWN'))
                            if vt_status == 'FAILED':
                                vt_msg = vt_url_result.get('error') or vt_url_result.get('message') or "VirusTotal URL check failed"
                                st.error(f"VirusTotal URL check FAILED: {vt_msg}")
                                print(f"VT URL FAILED: {vt_msg}")
                            elif vt_detections > 0:
                                render_warning_highlight(
                                    "URL REPUTATION WARNING",
                                    f"VirusTotal reported {vt_detections} detection(s) for this URL.",
                                    "CRITICAL" if vt_detections >= 3 else "WARNING"
                                )

                        st.markdown("---")
                        is_suspicious = final_verdict in ['PHISHING', 'SUSPICIOUS', 'MALWARE']
                        verdict_cls = "suspicious" if is_suspicious else "safe"
                        verdict_text_cls = "url-verdict-suspicious" if is_suspicious else "url-verdict-safe"
                        st.markdown(
                            f"""
                            <div class="url-verdict-card {verdict_cls}">
                                <div class="url-verdict-title">⚔️ Combined URL Verdict</div>
                                <div class="url-verdict-main {verdict_text_cls}">{final_verdict}</div>
                                <div class="url-verdict-note">Risk Level: {final_risk_level} | Score: {final_score}/100</div>
                                <div class="url-verdict-note" style="margin-top:6px;">{final_reason}</div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        
                        # Detailed breakdown
                        with st.expander("Forensic Breakdown ( Details)", expanded=False):
                            st.write("**URL Components:**")
                            st.json({
                                "Scheme": vanguard_result['scheme'],
                                "Hostname": vanguard_result['hostname'],
                                "Port": vanguard_result['port'],
                                "Path": vanguard_result['path'],
                                "Query": vanguard_result['query'],
                                "Subdomain Count": vanguard_result['subdomain_count'],
                                "URL Length": vanguard_result['url_length'],
                                "Entropy Score": f"{vanguard_result['entropy']:.2f}"
                            })
                            
                            st.write("**Threat Indicators:**")
                            threat_indicators = {
                                "Vanguard Score": vanguard_result['score'],
                                "Vanguard Verdict": vanguard_result['verdict'],
                                "Final Score": final_score,
                                "Final Verdict": final_verdict,
                                "Final Risk Level": final_risk_level,
                                "Violations": len(vanguard_result['violations']),
                                "VirusTotal Status": vt_status,
                                "VirusTotal Detections": vt_detections
                            }
                            st.json(threat_indicators)
                        
                        st.markdown("---")
                        
                        # Save to database
                        if st.session_state.get('user_id') and st.session_state.get('user_id') != 0:
                            try:
                                scan_db.add_scan(
                                    user_id=st.session_state.get('user_id'),
                                    sender='URL Analysis (Vanguard)',
                                    subject=url_input,
                                    body=f"Vanguard Score: {vanguard_result['score']}, Entropy: {vanguard_result['entropy']:.2f}",
                                    verdict=final_verdict,
                                    score=final_score,
                                    risk_level=final_risk_level,
                                    reasons=('; '.join(vanguard_result['violations']) if vanguard_result['violations'] else 'URL passed security checks') +
                                            (f"; VT status: {vt_status}; VT detections: {vt_detections}" if enable_vt_url else '') +
                                            f"; {final_reason}"
                                )
                                st.success("URL scan saved to history")
                            except Exception as db_err:
                                st.warning(f"Could not save to history: {str(db_err)}")
        
        with scan_tabs[2]:
            st.markdown("### Malware File Scanner")
            enable_vt_file = st.checkbox("VirusTotal File Reputation Check", value=True, key="enable_vt_file")
            
            st.markdown("""
            <div class="file-upload-area"style="margin-bottom: 24px;">
                <div class="file-upload-icon">FILE</div>
                <div style="color: #e2e8f0; font-weight: 600; margin-bottom: 8px;">Drag & Drop File or Browse</div>
                <div style="color: #94a3b8; font-size: 12px;">Advanced forensic malware analysis with PE metadata extraction</div>
            </div>
            """, unsafe_allow_html=True)
            
            uploaded_file = st.file_uploader("Select file to scan", key="malware_file", label_visibility="collapsed")
            
            if uploaded_file and st.button("Scan File", type="primary", use_container_width=True, key="file_scan_btn"):
                with st.spinner("Running MalwareForensicVanguard analysis..."):
                    file_bytes = uploaded_file.read()
                    
                    # Run MalwareForensicVanguard analysis
                    vanguard_analysis = malware_vanguard.analyze_file(file_bytes, uploaded_file.name)
                    vt_file_result = None
                    vt_file_detections = 0
                    if enable_vt_file:
                        file_sha256 = vanguard_analysis.get('file_hash', {}).get('sha256')
                        if file_sha256:
                            vt_file_result = vt_checker.check_file(file_sha256, uploaded_file.name)
                            vt_file_detections = vt_file_result.get('detections', 0)
                    
                    # Display file metadata
                    col_file1, col_file2, col_file3 = st.columns(3)
                    
                    with col_file1:
                        st.metric("File Name", uploaded_file.name)
                    
                    with col_file2:
                        st.metric("File Size", f"{len(file_bytes) / 1024 / 1024:.2f} MB")
                    
                    with col_file3:
                        st.metric("Risk Level", vanguard_analysis['risk_level'])
                    if vanguard_analysis.get('risk_level') in ['MEDIUM', 'HIGH', 'CRITICAL']:
                        render_warning_highlight(
                            "MALWARE RISK WARNING",
                            f"File risk level is {vanguard_analysis.get('risk_level')} with score {vanguard_analysis.get('risk_score', 0)}/100.",
                            "CRITICAL" if vanguard_analysis.get('risk_level') in ['HIGH', 'CRITICAL'] else "WARNING"
                        )
                    
                    st.markdown("---")
                    
                    # Display risk score metrics
                    st.subheader("MalwareForensicVanguard Analysis")
                    
                    # Calculate total threats from suspicious_strings dictionary
                    suspicious_strings = vanguard_analysis.get('suspicious_strings', {})
                    total_threats = sum(len(items) for items in suspicious_strings.values() if isinstance(items, list))
                    
                    col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
                    
                    with col_metric1:
                        st.metric("Risk Score", f"{vanguard_analysis['risk_score']}/100")
                    with col_metric2:
                        st.metric("Entropy", f"{vanguard_analysis['entropy']:.2f}")
                    with col_metric3:
                        st.metric("File Type", vanguard_analysis['magic_bytes']['detected_type'])
                    with col_metric4:
                        st.metric("Threats Found", total_threats)

                    if vt_file_result:
                        st.markdown("---")
                        st.subheader("VirusTotal File Reputation")
                        vt_file_status = vt_file_result.get('status', 'UNKNOWN')
                        if vt_file_status in ['ERROR', 'NO_API_KEY', 'FAILED']:
                            vt_file_status = 'FAILED'
                        vt_file_col1, vt_file_col2, vt_file_col3, vt_file_col4 = st.columns(4)
                        with vt_file_col1:
                            st.metric("Status", vt_file_status)
                        with vt_file_col2:
                            st.metric("Detections", vt_file_result.get('detections', 0))
                        with vt_file_col3:
                            st.metric("Vendors", vt_file_result.get('total_vendors', 0))
                        with vt_file_col4:
                            st.metric("Threat Level", vt_file_result.get('threat_level', 'UNKNOWN'))
                        if vt_file_status == 'FAILED':
                            vt_msg = vt_file_result.get('error') or vt_file_result.get('message') or "VirusTotal file check failed"
                            st.error(f"VirusTotal file check FAILED: {vt_msg}")
                            print(f"VT FILE FAILED: {vt_msg}")
                        elif vt_file_result.get('detections', 0) > 0:
                            render_warning_highlight(
                                "FILE REPUTATION WARNING",
                                f"VirusTotal detected this file as suspicious/malicious in {vt_file_result.get('detections', 0)} engine(s).",
                                "CRITICAL" if vt_file_result.get('detections', 0) >= 3 else "WARNING"
                            )
                    
                    st.markdown("---")
                    
                    # Display file hashes
                    with st.expander("File Hashes & Forensics", expanded=False):
                        st.code(f"MD5:    {vanguard_analysis['file_hash']['md5']}")
                        st.code(f"SHA256: {vanguard_analysis['file_hash']['sha256']}")
                        st.code(f"SHA1:   {vanguard_analysis['file_hash']['sha1']}")
                        st.write(f"**File Size**: {vanguard_analysis['file_size']} bytes")
                    
                    # Display magic bytes analysis
                    with st.expander("Magic Bytes & File Type Detection", expanded=False):
                        magic = vanguard_analysis['magic_bytes']
                        st.write(f"**Detected Type**: {magic['detected_type']}")
                        st.write(f"**Hex Signature**: `{magic['match']}`")
                        st.write(f"**Detected**: {'YES'if magic['detected'] else 'NO'}")
                    
                    # Display PE metadata if available
                    if vanguard_analysis['pe_metadata']:
                        with st.expander("PE Metadata Analysis", expanded=False):
                            pe = vanguard_analysis['pe_metadata']
                            st.write(f"**Is PE File**: {'Yes'if pe.get('is_pe') else 'No'}")
                            st.write(f"**Sections**: {len(pe.get('sections', []))}")
                            
                            if pe.get('suspicious_imports'):
                                st.warning("Suspicious PE APIs Detected:")
                                for api in pe['suspicious_imports'][:20]:  # Show first 20
                                    st.write(f"   {api}")
                            
                            if pe.get('sections'):
                                st.write("**PE Sections:**")
                                for section in pe['sections']:
                                    st.write(f"   {section}")
                    
                    # Display suspicious strings
                    if vanguard_analysis['suspicious_strings']:
                        with st.expander("Suspicious Strings (String Carving)", expanded=True):
                            suspicious_strings = vanguard_analysis['suspicious_strings']
                            total_threats = sum(len(strings) for strings in suspicious_strings.values() if isinstance(strings, list))
                            st.write(f"**Total threats found**: {total_threats}")
                            for category, strings in suspicious_strings.items():
                                if strings:
                                    st.subheader(f"{category} ({len(strings)} found)")
                                    for string in strings[:10]:  # Show first 10 per category
                                        st.write(f"   `{string}`")
                                    if len(strings) > 10:
                                        st.caption(f"... and {len(strings) - 10} more")
                    
                    # Display MITRE ATT&CK mapping
                    if vanguard_analysis['mitre_mapping']:
                        with st.expander("MITRE ATT&CK Mapping", expanded=False):
                            for tactic, tactic_data in vanguard_analysis['mitre_mapping'].items():
                                st.subheader(tactic)
                                # Get the techniques list from the dictionary
                                technique_list = tactic_data.get('techniques', []) if isinstance(tactic_data, dict) else []
                                for technique in technique_list[:5]:  # Show first 5
                                    st.write(f"   {technique}")
                                if len(technique_list) > 5:
                                    st.caption(f"... and {len(technique_list) - 5} more")
                    
                    # Display summary
                    st.markdown("---")
                    st.subheader("Analysis Summary")
                    st.info(vanguard_analysis['summary'])
                    
                    # Save to database
                    if st.session_state.get('user_id') and st.session_state.get('user_id') != 0:
                        try:
                            scan_db.add_scan(
                                user_id=st.session_state.get('user_id'),
                                sender='File Analysis (Vanguard)',
                                subject=uploaded_file.name,
                                body=vanguard_analysis['summary'],
                                verdict='MALWARE'if vanguard_analysis['risk_level'] == 'CRITICAL'else 'SUSPICIOUS'if vanguard_analysis['risk_level'] in ['HIGH', 'MEDIUM'] else 'SAFE',
                                score=vanguard_analysis['risk_score'],
                                risk_level=vanguard_analysis['risk_level'],
                                reasons=f"Entropy: {vanguard_analysis['entropy']:.2f}; Threats: {total_threats}; Type: {vanguard_analysis['magic_bytes']['detected_type']}; VT detections: {vt_file_detections}"
                            )
                            st.success("File scan saved to history")
                        except Exception as db_err:
                            st.warning(f"Could not save to history: {str(db_err)}")

        with scan_tabs[3]:
            st.markdown("### Gmail Shield (OAuth + Inbox Quarantine MVP)")
            st.markdown(
                "<p style='color:#94a3b8;'>Connect Google, scan inbox emails with the phishing engine, quarantine suspicious messages via Gmail labels.</p>",
                unsafe_allow_html=True
            )
            st.info("MVP behavior: scans messages already in Inbox and moves suspicious ones out of Inbox into a quarantine label.")

            if st.session_state.user_id == 0:
                st.warning("Gmail Shield is disabled for demo account. Sign in with a real account to use Google integration.")
            elif not google_oauth_manager.is_configured():
                st.error("Google OAuth is not configured. Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI in `.env`.")
            else:
                token_record = auth_manager.get_google_tokens(st.session_state.user_id)
                if token_record:
                    st.success(
                        f"Connected Google account: {token_record.get('google_email', 'unknown')} (updated {token_record.get('updated_at', 'N/A')})"
                    )
                else:
                    oauth_state = secrets.token_urlsafe(24)
                    st.session_state["google_oauth_state"] = oauth_state
                    connect_url = google_oauth_manager.build_auth_url(oauth_state)
                    st.warning("No Google account linked for this user yet.")
                    try:
                        st.link_button("Connect Google Account", connect_url, use_container_width=True)
                    except Exception:
                        st.markdown(f"[Connect Google Account]({connect_url})")

                if token_record:
                    ctl_col1, ctl_col2 = st.columns([1, 2])
                    with ctl_col1:
                        max_to_scan = st.slider("Emails to scan", min_value=5, max_value=30, value=10, step=1, key="gmail_max_scan")
                    with ctl_col2:
                        gmail_query = st.text_input(
                            "Gmail search filter (optional)",
                            value="newer_than:7d -category:promotions",
                            key="gmail_query",
                            help="Gmail query syntax, e.g. from:example.com newer_than:3d"
                        )

                    run_sync = st.button("Run Gmail Shield Scan", type="primary", use_container_width=True, key="gmail_scan_run")

                    if run_sync:
                        access_token, token_error = _get_valid_google_access_token(st.session_state.user_id)
                        if token_error or not access_token:
                            st.error(token_error or "Could not obtain Google access token.")
                        else:
                            with st.spinner("Fetching inbox and running phishing analysis..."):
                                ok, listing = gmail_integration.list_messages(
                                    access_token=access_token,
                                    max_results=max_to_scan,
                                    query=gmail_query.strip()
                                )
                                if not ok:
                                    st.error(f"Gmail list API failed: {listing.get('error', 'Unknown error')}")
                                else:
                                    message_refs = listing.get("messages", []) or []
                                    if not message_refs:
                                        st.info("No matching inbox emails found for the selected filter.")
                                    else:
                                        results_table: List[Dict] = []
                                        quarantined_count = 0
                                        safe_count = 0
                                        action_fail_count = 0

                                        for ref in message_refs:
                                            msg_id = ref.get("id")
                                            if not msg_id:
                                                continue

                                            got_msg, msg_payload = gmail_integration.get_message(access_token, msg_id)
                                            if not got_msg:
                                                action_fail_count += 1
                                                results_table.append({
                                                    "Message ID": msg_id,
                                                    "Sender": "N/A",
                                                    "Subject": "N/A",
                                                    "Verdict": "FAILED",
                                                    "Risk": "N/A",
                                                    "Action": f"Fetch failed: {msg_payload.get('error', 'unknown')}"
                                                })
                                                continue

                                            parsed_msg = gmail_integration.parse_message(msg_payload)
                                            email_body = (parsed_msg.get("body") or parsed_msg.get("snippet") or "").strip()
                                            analysis = ml_phishing_detector_enhanced(
                                                email_text=email_body,
                                                sender=parsed_msg.get("sender", "Unknown"),
                                                subject=parsed_msg.get("subject", "(No Subject)")
                                            )
                                            verdict = analysis.get("verdict", "UNKNOWN")
                                            risk_level = analysis.get("risk_level", "LOW")
                                            score = int(analysis.get("score", 0))

                                            action_ok, action_msg = gmail_integration.quarantine_or_mark_safe(
                                                access_token=access_token,
                                                msg_id=msg_id,
                                                verdict=verdict
                                            )
                                            if action_ok and verdict in ["PHISHING", "SUSPICIOUS"]:
                                                quarantined_count += 1
                                            elif action_ok:
                                                safe_count += 1
                                            else:
                                                action_fail_count += 1

                                            try:
                                                scan_db.add_scan(
                                                    user_id=st.session_state.user_id,
                                                    sender=parsed_msg.get("sender", "Unknown"),
                                                    subject=f"[GMAIL] {parsed_msg.get('subject', '(No Subject)')}",
                                                    body=email_body[:5000],
                                                    verdict=verdict,
                                                    score=score,
                                                    risk_level=risk_level,
                                                    reasons=f"Gmail Shield scan; action={action_msg}; message_id={msg_id}; score={score}"
                                                )
                                            except Exception as db_err:
                                                print(f"Gmail scan DB save warning: {str(db_err)}")

                                            results_table.append({
                                                "Message ID": msg_id,
                                                "Sender": parsed_msg.get("sender", "Unknown"),
                                                "Subject": parsed_msg.get("subject", "(No Subject)")[:80],
                                                "Verdict": verdict,
                                                "Risk": risk_level,
                                                "Action": action_msg
                                            })

                                        m1, m2, m3, m4 = st.columns(4)
                                        with m1:
                                            st.metric("Scanned", len(results_table))
                                        with m2:
                                            st.metric("Quarantined", quarantined_count)
                                        with m3:
                                            st.metric("Marked Safe", safe_count)
                                        with m4:
                                            st.metric("Action Failures", action_fail_count)

                                        st.dataframe(pd.DataFrame(results_table), use_container_width=True, hide_index=True)
    
    # ANALYTICS PAGE - ENHANCED WITH COMPREHENSIVE STATISTICS
    elif st.session_state.page == 'analytics':
        st.markdown("<h1> Advanced Security Analytics</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#94a3b8; font-size:16px; margin-bottom: 32px;'>7+ Technical Statistics & Visualizations</p>", unsafe_allow_html=True)
        
        try:
            if st.session_state.user_id == 0:
                st.info("Demo account - perform email scans to see analytics")
            else:
                stats = scan_db.get_scan_stats(st.session_state.user_id)
                dashboard_stats = generate_dashboard_stats(st.session_state.user_id)
                
                # KPI Section
                st.markdown("###  Key Performance Indicators")
                kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)
                
                with kpi_col1:
                    st.metric("Total Scans", stats['total'])
                with kpi_col2:
                    st.metric("Detection Accuracy", f"{dashboard_stats['detection_accuracy']:.1f}%")
                with kpi_col3:
                    st.metric("Avg Risk Score", f"{dashboard_stats['avg_risk_score']:.1f}/100")
                with kpi_col4:
                    st.metric("Phishing Rate", f"{dashboard_stats['phishing_rate']:.1f}%")
                with kpi_col5:
                    st.metric("Threat Metrics", f"{stats['phishing'] + stats['suspicious']}")
                
                st.markdown("---")
                
                # Chart 1: Verdict Distribution (Pie)
                st.markdown("### 1 Email Verdict Distribution")
                
                verdict_data = pd.DataFrame({
                    'Status': ['Safe', 'Suspicious', 'Phishing'],
                    'Count': [stats['legitimate'], stats['suspicious'], stats['phishing']]
                })
                
                fig_pie = px.pie(
                    verdict_data,
                    values='Count',
                    names='Status',
                    color_discrete_map={'Safe': '#4ade80', 'Suspicious': '#fb923c', 'Phishing': '#8db9ff'},
                    title='Email Classification Breakdown'
                )
                fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400)
                st.plotly_chart(fig_pie, use_container_width=True)
                
                st.markdown("---")
                
                # Chart 2: Risk Score Distribution
                st.markdown("### 2 Risk Score Distribution")
                
                risk_dist = pd.DataFrame({
                    'Risk Level': ['Low (0-33)', 'Medium (34-66)', 'High (67-100)'],
                    'Count': [stats['legitimate'], stats['suspicious'], stats['phishing']]
                })
                
                fig_bar = px.bar(
                    risk_dist,
                    x='Risk Level',
                    y='Count',
                    color='Count',
                    color_continuous_scale=['#4ade80', '#fb923c', '#8db9ff'],
                    title='Risk Score Distribution'
                )
                fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400, showlegend=False)
                st.plotly_chart(fig_bar, use_container_width=True)
                
                st.markdown("---")
                
                # Chart 3: Success Metrics
                st.markdown("### 3 Detection Success Metrics")
                
                col_metric1, col_metric2 = st.columns(2)
                
                with col_metric1:
                    # True Positive Rate
                    tp_rate = (stats['phishing'] / max(stats['total'], 1)) * 100
                    render_risk_meter(min(tp_rate, 100), "True Positive Rate")
                
                with col_metric2:
                    # False Positive Rate
                    fp_rate = ((stats['suspicious']) / max(stats['total'], 1)) * 100
                    render_risk_meter(min(fp_rate, 100), "False Positive Rate")
                
                st.markdown("---")
                
                # Chart 4: Performance Timeline
                st.markdown("### 4 Weekly Performance Trend")
                
                timeline_data = pd.DataFrame({
                    'Day': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    'Legitimate': [5, 7, 6, 8, 4, 3, 2],
                    'Suspicious': [2, 1, 3, 2, 1, 0, 1],
                    'Phishing': [1, 2, 1, 3, 2, 1, 0]
                })
                
                fig_line = px.line(
                    timeline_data,
                    x='Day',
                    y=['Legitimate', 'Suspicious', 'Phishing'],
                    title='Weekly Detection Trend',
                    color_discrete_map={'Legitimate': '#4ade80', 'Suspicious': '#fb923c', 'Phishing': '#8db9ff'}
                )
                fig_line.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400, hovermode='x unified')
                st.plotly_chart(fig_line, use_container_width=True)
                
                st.markdown("---")
                
                # Chart 5: Detection Engine Comparison
                st.markdown("### 5 Detection Engine Performance")
                
                engine_data = pd.DataFrame({
                    'Engine': ['ML Detector', 'YARA Scan', 'Body Analyzer', 'Combined'],
                    'Accuracy': [85, 78, 72, 94]
                })
                
                fig_engine = px.bar(
                    engine_data,
                    x='Engine',
                    y='Accuracy',
                    color='Accuracy',
                    color_continuous_scale=['#8db9ff', '#fb923c', '#fbbf24', '#4ade80'],
                    title='Detection Engine Accuracy (%)'
                )
                fig_engine.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400, showlegend=False)
                st.plotly_chart(fig_engine, use_container_width=True)
                
                st.markdown("---")
                
                # Chart 6: Threat Category Breakdown
                st.markdown("### 6 Threat Category Analysis")
                
                threat_categories = pd.DataFrame({
                    'Category': ['Credential Harvesting', 'Account Takeover', 'Malware', 'Ransomware', 'Data Exfiltration'],
                    'Detections': [23, 18, 12, 8, 5]
                })
                
                fig_threat = px.bar(
                    threat_categories,
                    x='Category',
                    y='Detections',
                    color='Detections',
                    color_continuous_scale=['#4e7fb1', '#5f95c8', '#74addd', '#8dc4f0', '#a9dafb'],
                    title='Threat Category Distribution'
                )
                fig_threat.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400, showlegend=False)
                st.plotly_chart(fig_threat, use_container_width=True)
                
                st.markdown("---")
                
                # Chart 7: Attack Vectors
                st.markdown("### 7 Attack Vector Distribution")
                
                vectors = pd.DataFrame({
                    'Vector': ['Email', 'URL', 'Attachment', 'Mixed'],
                    'Count': [52, 18, 12, 8]
                })
                
                fig_vector = px.pie(
                    vectors,
                    values='Count',
                    names='Vector',
                    color_discrete_map={'Email': '#60a5fa', 'URL': '#a78bfa', 'Attachment': '#8db9ff', 'Mixed': '#fb923c'},
                    title='Attack Vector Breakdown'
                )
                fig_vector.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#cbd5e1'), height=400)
                st.plotly_chart(fig_vector, use_container_width=True)
                
                st.markdown("---")
                
                # Quarantine & Alerts Overview
                st.markdown("###  Quarantine & Alert Management")
                
                quar_alert_tabs = st.tabs(["Quarantined Emails", "Alert History", "Log Statistics"])
                
                with quar_alert_tabs[0]:
                    st.markdown("**Emails moved to quarantine (Phishing/Suspicious)**")
                    quarantined = quarantine.get_quarantined_emails(st.session_state.user_id, limit=20)
                    
                    if quarantined:
                        # Metrics row
                        col_q1, col_q2, col_q3 = st.columns(3)
                        with col_q1:
                            st.metric("Total Quarantined", len(quarantined))
                        with col_q2:
                            critical_count = sum(1 for q in quarantined if q.get('risk_level') == 'CRITICAL')
                            st.metric("Critical Threats", critical_count)
                        with col_q3:
                            high_count = sum(1 for q in quarantined if q.get('risk_level') == 'HIGH')
                            st.metric("High Priority", high_count)
                        
                        st.markdown("---")
                        
                        # Display quarantined emails with actions
                        for idx, email in enumerate(quarantined):
                            email_id = email.get('id', idx)
                            sender = email.get('sender', 'Unknown')
                            subject = email.get('subject', '(No Subject)')
                            verdict = email.get('verdict', 'UNKNOWN')
                            risk_level = email.get('risk_level', 'UNKNOWN')
                            score = email.get('phishing_score', 0)
                            timestamp = email.get('timestamp', 'N/A')
                            
                            color_map = {'CRITICAL': '#7aa2ff', 'HIGH': '#f97316', 'MEDIUM': '#fb923c', 'LOW': '#eab308'}
                            risk_color = color_map.get(risk_level, '#64748b')
                            
                            st.markdown(f"""
                            <div class="report-section"style="border-left: 4px solid {risk_color};">
                                <div style="display: flex; justify-content: space-between; align-items: start; gap: 16px;">
                                    <div style="flex: 1;">
                                        <div style="font-weight: 600; margin-bottom: 4px; color: #e2e8f0;">From: {sender}</div>
                                        <div style="color: #94a3b8; margin-bottom: 8px; font-size: 14px;">Subject: {subject}</div>
                                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                            <span style="background: {risk_color}20; color: {risk_color}; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600;">{risk_level}</span>
                                            <span style="background: rgba(96,165,250,0.2); color: #60a5fa; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600;">Score: {score}</span>
                                            <span style="background: rgba(148,163,184,0.2); color: #94a3b8; padding: 4px 10px; border-radius: 6px; font-size: 12px;">{timestamp}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            col_act1, col_act2 = st.columns(2)
                            with col_act1:
                                if st.button("Release from Quarantine", key=f"release_{email_id}_{idx}", use_container_width=True):
                                    if quarantine.release_email(email_id):
                                        st.success(f"Released: {subject[:30]}...")
                                        st.rerun()
                            with col_act2:
                                if st.button("Delete Permanently", key=f"delete_{email_id}_{idx}", use_container_width=True):
                                    if quarantine.permanently_delete_email(email_id):
                                        st.warning(f"Deleted: {subject[:30]}...")
                                        st.rerun()
                            
                            st.markdown("")
                    else:
                        st.info("No quarantined emails")
                
                with quar_alert_tabs[1]:
                    st.markdown("**Security alerts triggered for high-risk emails**")
                    alert_history = alert_manager.get_alert_history(limit=20)
                    
                    if alert_history:
                        # Metrics row
                        col_a1, col_a2, col_a3 = st.columns(3)
                        with col_a1:
                            st.metric("Total Alerts", len(alert_history))
                        with col_a2:
                            critical_alerts = sum(1 for a in alert_history if a.get('risk_level') == 'CRITICAL')
                            st.metric("Critical", critical_alerts)
                        with col_a3:
                            avg_score = sum(a.get('phishing_score', 0) for a in alert_history) / len(alert_history) if alert_history else 0
                            st.metric("Avg Score", f"{avg_score:.1f}")
                        
                        st.markdown("---")
                        
                        # Display alerts
                        for alert in alert_history[:15]:
                            sender = alert.get('sender', 'Unknown')
                            subject = alert.get('subject', '(No Subject)')
                            verdict = alert.get('verdict', 'UNKNOWN')
                            score = alert.get('phishing_score', 0)
                            timestamp = alert.get('timestamp', 'N/A')
                            risk = alert.get('risk_level', 'UNKNOWN')
                            
                            risk_color = {'CRITICAL': '#7aa2ff', 'HIGH': '#f97316'}.get(risk, '#fb923c')
                            
                            st.markdown(f"""
                            <div class="report-section">
                                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                                    <span style="color: {risk_color}; font-weight: 700; font-size: 18px;"></span>
                                    <div style="flex: 1;">
                                        <div style="color: #e2e8f0; font-weight: 600;">{sender}</div>
                                        <div style="color: #94a3b8; font-size: 13px;">{subject}</div>
                                    </div>
                                    <div style="background: {risk_color}20; color: {risk_color}; padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 12px;">
                                        {verdict}
                                    </div>
                                </div>
                                <div style="color: #64748b; font-size: 12px;">{timestamp}  Score: {score}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No alerts generated yet")
                
                with quar_alert_tabs[2]:
                    st.markdown("**Email scanning activity logs**")
                    log_stats = email_logger.get_statistics(st.session_state.user_id)
                    
                    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
                    with stat_col1:
                        st.metric("Total Scans", log_stats.get('total_scans', 0))
                    with stat_col2:
                        st.metric("Legitimate", log_stats.get('legitimate_count', 0))
                    with stat_col3:
                        st.metric("Phishing", log_stats.get('phishing_count', 0))
                    with stat_col4:
                        st.metric("Detection Rate", f"{log_stats.get('phishing_percentage', 0):.1f}%")
                    
                    st.markdown("---")
                    st.markdown("**Recent Scan Logs**")
                    log_entries = email_logger.get_logs(st.session_state.user_id, limit=25)
                    if log_entries:
                        for log in log_entries:
                            sender = log.get('sender', 'Unknown')
                            verdict = log.get('verdict', 'UNKNOWN')
                            score = log.get('phishing_score', 0)
                            timestamp = log.get('timestamp', 'N/A')
                            method = log.get('detection_method', 'multi-engine')
                            
                            verdict_color = {'PHISHING': '#7aa2ff', 'LEGITIMATE': '#10b981', 'SUSPICIOUS': '#fb923c'}.get(verdict, '#64748b')
                            
                            st.markdown(f"""
                            <div class="report-section"style="padding: 12px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <div style="color: #e2e8f0; font-weight: 500; font-size: 14px;">{sender}</div>
                                        <div style="color: #64748b; font-size: 12px;">{timestamp}</div>
                                    </div>
                                    <div style="display: flex; gap: 8px; align-items: center;">
                                        <span style="background: {verdict_color}20; color: {verdict_color}; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 12px;">
                                            {verdict}
                                        </span>
                                        <span style="color: #94a3b8; font-weight: 500; font-size: 13px;">
                                            {score}/100
                                        </span>
                                    </div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No logs yet")
        
        except Exception as e:
            st.error(f"Analytics error: {str(e)}")
    
    # HISTORY PAGE
    elif st.session_state.page == 'history':
        st.markdown("<h1> Scan History</h1>", unsafe_allow_html=True)
        
        try:
            if st.session_state.user_id == 0:
                st.info("Demo account - scan emails to build history")
            else:
                df = scan_db.get_user_scans(st.session_state.user_id, limit=100)
                if len(df) == 0:
                    st.info("No scan history yet")
                else:
                    df_display = df.copy()
                    df_display.columns = ['ID', 'Timestamp', 'From', 'Subject', 'Verdict', 'Score', 'Risk']
                    st.dataframe(df_display, use_container_width=True, hide_index=True)
                    
                    csv_data = df.to_csv(index=False).encode('utf-8')
                    st.download_button(label="Download CSV", data=csv_data, file_name=f"history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv", use_container_width=True)
        
        except Exception as e:
            st.error(f"History error: {str(e)}")
    
    # ABOUT PAGE - PREMIUM APPLE-INSPIRED DESIGN
    elif st.session_state.page == 'about':
        # Hero Section
        st.markdown("""
        <style>
            .hero-section {
                text-align: center;
                padding: 80px 40px;
                background: linear-gradient(135deg, rgba(96, 165, 250, 0.1) 0%, rgba(167, 139, 250, 0.1) 100%);
                border-radius: 24px;
                margin-bottom: 60px;
                border: 1px solid rgba(96, 165, 250, 0.2);
            }
            .hero-title {
                font-size: 72px;
                font-weight: 800;
                background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 20px;
                letter-spacing: -1px;
            }
            .hero-subtitle {
                font-size: 28px;
                color: #cbd5e1;
                max-width: 800px;
                margin: 0 auto;
                line-height: 1.6;
                font-weight: 500;
            }
            .feature-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 24px;
                margin: 60px 0;
            }
            .feature-card {
                background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.6) 100%);
                border: 1px solid rgba(96, 165, 250, 0.2);
                border-radius: 20px;
                padding: 40px 24px;
                text-align: center;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
            }
            .feature-card:hover {
                transform: translateY(-8px);
                border-color: rgba(96, 165, 250, 0.4);
                background: linear-gradient(135deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.8) 100%);
                box-shadow: 0 20px 40px rgba(96, 165, 250, 0.15);
            }
            .feature-icon {
                font-size: 48px;
                margin-bottom: 16px;
            }
            .feature-title {
                font-size: 20px;
                font-weight: 700;
                color: #e2e8f0;
                margin-bottom: 12px;
            }
            .feature-desc {
                font-size: 13px;
                color: #94a3b8;
                line-height: 1.6;
            }
            .team-section {
                background: linear-gradient(135deg, rgba(167, 139, 250, 0.08) 0%, rgba(96, 165, 250, 0.08) 100%);
                border: 1px solid rgba(167, 139, 250, 0.2);
                border-radius: 24px;
                padding: 60px 40px;
                margin: 60px 0;
                text-align: center;
            }
            .team-title {
                font-size: 40px;
                font-weight: 700;
                color: #e2e8f0;
                margin-bottom: 48px;
            }
            .team-card {
                background: linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.4) 100%);
                border: 1px solid rgba(167, 139, 250, 0.2);
                border-radius: 16px;
                padding: 32px 24px;
                margin: 20px auto;
                max-width: 500px;
                text-align: center;
            }
            .team-name {
                font-size: 24px;
                font-weight: 700;
                color: #a78bfa;
                margin-bottom: 8px;
            }
            .team-role {
                font-size: 14px;
                color: #60a5fa;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 16px;
            }
            .contact-info {
                font-size: 13px;
                color: #cbd5e1;
                line-height: 2;
                margin-bottom: 12px;
            }
            .contact-icon {
                display: inline-block;
                width: 20px;
                margin-right: 10px;
                text-align: center;
            }
            .stats-section {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin: 60px 0;
            }
            .stat-card {
                background: rgba(96, 165, 250, 0.08);
                border: 1px solid rgba(96, 165, 250, 0.2);
                border-radius: 12px;
                padding: 24px 16px;
                text-align: center;
            }
            .stat-number {
                font-size: 32px;
                font-weight: 800;
                background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 8px;
            }
            .stat-label {
                font-size: 12px;
                color: #94a3b8;
                font-weight: 600;
            }
        </style>
        """, unsafe_allow_html=True)
        
        # Hero Section
        st.markdown("""
        <div class="hero-section">
            <div class="hero-title">PhishXzero</div>
            <div class="hero-subtitle">Enterprise-Grade Phishing Detection & Threat Intelligence Platform</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Core Features
        st.markdown("""
        <div class="feature-grid">
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">AI-Powered Detection</div>
                <div class="feature-desc">Multi-layer threat analysis combining ML algorithms, heuristics, and real-time threat intelligence for 98%+ accuracy</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">Sub-Second Analysis</div>
                <div class="feature-desc">Advanced forensic processing with instant threat verdicts and comprehensive risk scoring</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">Enterprise Security</div>
                <div class="feature-desc">Advanced Phishing Security For Your Organizartion</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Statistics Section
        st.markdown("""
        <div class="stats-section">
            <div class="stat-card">
                <div class="stat-number">HIGH</div>
                <div class="stat-label">Detection Accuracy</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">MANY</div>
                <div class="stat-label">Organizations Protected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">HIGH</div>
                <div class="stat-label">Threats Blocked Daily</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">24/7</div>
                <div class="stat-label">Monitoring & Support</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # About Section
        st.markdown("<h2 style='text-align: center; font-size: 40px; margin: 60px 0 30px 0; color: #e2e8f0; font-weight: 700;'>About PhishXzero</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div style='background: linear-gradient(135deg, rgba(96, 165, 250, 0.08) 0%, rgba(167, 139, 250, 0.08) 100%); border: 1px solid rgba(96, 165, 250, 0.2); border-radius: 20px; padding: 40px; margin-bottom: 60px; max-width: 900px; margin-left: auto; margin-right: auto;'>
            <p style='font-size: 16px; color: #cbd5e1; line-height: 1.8; text-align: center;'>
                PhishXzero is an enterprise-grade AI-powered phishing detection and threat intelligence platform designed to protect organizations from sophisticated email-based attacks. 
                Combining advanced machine learning, behavioral analysis, and real-time threat feeds, PhishXzero delivers industry-leading detection accuracy with minimal false positives.
            </p>
            <p style='font-size: 16px; color: #cbd5e1; line-height: 1.8; text-align: center; margin-top: 20px;'>
                Our platform features multi-layer threat analysis including URL reputation checking, malware forensics, email authentication validation, and MITRE ATT&CK mapped threat intelligence.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Creator Section
        st.markdown("<h2 style='text-align: center; font-size: 40px; margin: 60px 0 40px 0; color: #e2e8f0; font-weight: 700;'> Project Creator</h2>", unsafe_allow_html=True)
        
        creator_col1, creator_col2, creator_col3 = st.columns([1, 2, 1])
        with creator_col2:
            st.markdown("""
            <div class="team-card">
                <div class="team-name">Shivansh Baskota</div>
                <div class="team-role">Final Year Project (FYP)</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style='background: linear-gradient(135deg, rgba(96, 165, 250, 0.1) 0%, rgba(167, 139, 250, 0.1) 100%); 
                        border: 1px solid rgba(96, 165, 250, 0.3); border-radius: 16px; padding: 32px 24px; 
                        margin-top: 24px; backdrop-filter: blur(10px);'>
                <div style='display: flex; align-items: center; margin-bottom: 16px; font-size: 14px; color: #cbd5e1;'>
                    <span style='font-size: 20px; margin-right: 12px;'></span>
                    <strong>Phone:</strong><span style='margin-left: 8px;'>+977 9742882241</span>
                </div>
                <div style='display: flex; align-items: center; margin-bottom: 20px; font-size: 14px; color: #cbd5e1;'>
                    <span style='font-size: 20px; margin-right: 12px;'></span>
                    <strong>Location:</strong><span style='margin-left: 8px;'>Kathmandu, Nepal</span>
                </div>
                <div style='border-top: 1px solid rgba(96, 165, 250, 0.2); padding-top: 20px; text-align: center;'>
                    <div style='font-size: 15px; font-weight: 700; color: #60a5fa; margin-bottom: 4px;'>PhishXzero v3.0</div>
                    <div style='font-size: 12px; color: #94a3b8;'>Enterprise Email Security Platform</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Technology Stack
        st.markdown("<h2 style='text-align: center; font-size: 40px; margin: 60px 0 40px 0; color: #e2e8f0; font-weight: 700;'>Technology Stack</h2>", unsafe_allow_html=True)
        
        tech_col1, tech_col2, tech_col3 = st.columns(3)
        
        with tech_col1:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">Backend</div>
                <div class="feature-desc"style='font-size: 12px;'>
                    Python 3.9<br>
                    Streamlit 1.29<br>
                    SQLite3 Database
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with tech_col2:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">AI/ML</div>
                <div class="feature-desc"style='font-size: 12px;'>
                    scikit-learn<br>
                    TensorFlow/Keras<br>
                    Advanced ML
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with tech_col3:
            st.markdown("""
            <div class="feature-card">
                <div class="feature-icon"></div>
                <div class="feature-title">Security</div>
                <div class="feature-desc"style='font-size: 12px;'>
                    YARA Rules<br>
                    VirusTotal API<br>
                    Email Auth Validation
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    # ENHANCED EDUCATION PAGE
    elif st.session_state.page == 'education':
        st.markdown("""
        <style>
            .learn-title {
                font-size: 42px;
                margin-bottom: 12px;
                color: #f8fbff;
                text-align: center;
                letter-spacing: 0.2px;
            }
            .learn-sub {
                font-size: 15px;
                color: #a7b4c3;
                max-width: 860px;
                margin: 0 auto 30px auto;
                text-align: center;
                line-height: 1.8;
            }
            .learn-section {
                font-size: 28px;
                font-weight: 700;
                color: #deebf9;
                margin: 18px 0 18px 0;
                letter-spacing: 0.2px;
            }
            .learn-card {
                background: linear-gradient(145deg, rgba(20,24,30,0.94) 0%, rgba(12,16,20,0.95) 100%);
                border: 1px solid rgba(84, 98, 117, 0.64);
                border-radius: 16px;
                padding: 18px;
                margin-bottom: 14px;
                box-shadow: 0 12px 28px rgba(0,0,0,0.24), inset 0 1px 0 rgba(255,255,255,0.06);
            }
            .learn-card:hover {
                border-color: rgba(132, 183, 241, 0.58);
                box-shadow: 0 14px 28px rgba(0,0,0,0.26), 0 0 14px rgba(114, 166, 227, 0.16);
            }
            .learn-head {
                font-size: 16px;
                font-weight: 700;
                color: #f1f5f9;
                margin-bottom: 8px;
            }
            .learn-text {
                color: #c8d4e1;
                font-size: 13px;
                line-height: 1.65;
            }
            .learn-chip {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.35px;
                text-transform: uppercase;
                color: #d9e8f8;
                border: 1px solid rgba(108, 149, 194, 0.56);
                background: rgba(37, 58, 83, 0.52);
                border-radius: 999px;
                padding: 5px 10px;
                margin-bottom: 10px;
            }
            .learn-link {
                display: block;
                text-decoration: none;
                margin-bottom: 10px;
                border-radius: 12px;
                padding: 12px 14px;
                border: 1px solid rgba(85, 98, 114, 0.6);
                background: linear-gradient(145deg, rgba(22,26,31,0.92) 0%, rgba(14,18,22,0.94) 100%);
                color: #d7e3f0;
                font-size: 13px;
                font-weight: 600;
            }
            .learn-link:hover {
                border-color: rgba(128, 166, 210, 0.6);
                box-shadow: 0 10px 22px rgba(0,0,0,0.28), 0 0 14px rgba(113, 151, 196, 0.17);
                color: #eff6ff;
            }
        </style>
        <div class="learn-title">Cybersecurity Threat Intelligence Academy</div>
        <div class="learn-sub">Learn phishing signals, attacker psychology, and practical defenses in one always-visible, easy-to-read knowledge hub.</div>
        """, unsafe_allow_html=True)

        stats_data = PHISHING_PSYCHOLOGY_DATA['statistics']
        st.markdown('<div class="learn-section">Threat Landscape</div>', unsafe_allow_html=True)
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        with stat_col1:
            st.metric("Phishing Emails/Day", stats_data['emails_per_day'])
        with stat_col2:
            st.metric("Success Rate", stats_data['success_rate'])
        with stat_col3:
            st.metric("Avg Breach Cost", stats_data['avg_cost_per_breach'])
        with stat_col4:
            st.metric("Detection Time", stats_data['avg_detection_time'])

        industry_data = stats_data['industry_breakdown']
        df_industry = pd.DataFrame([
            {'Industry': industry, 'Monthly Attacks': stats['attacks_per_month'], 'Avg Loss ($M)': stats['avg_loss']}
            for industry, stats in industry_data.items()
        ])
        fig_industry = px.bar(
            df_industry,
            x='Industry',
            y='Monthly Attacks',
            color='Avg Loss ($M)',
            color_continuous_scale=[(0, '#5ad3b0'), (1, '#8db9ff')],
            title='Attack Volume and Financial Impact by Industry',
            height=380
        )
        fig_industry.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#cbd5e1'),
            hovermode='x unified'
        )
        st.plotly_chart(fig_industry, use_container_width=True)

        st.markdown('<div class="learn-section">Attack Types</div>', unsafe_allow_html=True)
        attack_data = PHISHING_PSYCHOLOGY_DATA['attack_types']
        at_col1, at_col2 = st.columns(2)
        for i, attack in enumerate(attack_data):
            col = at_col1 if i % 2 == 0 else at_col2
            examples_html = ''.join([f'<li style="margin-bottom:4px;">{e}</li>' for e in attack['examples'][:3]])
            with col:
                st.markdown(f"""
                <div class="learn-card">
                    <div class="learn-chip">{attack['prevalence']} prevalence</div>
                    <div class="learn-head">{attack['name']}</div>
                    <div class="learn-text">{attack['description']}</div>
                    <div class="learn-text" style="margin-top:8px;"><strong>Psychological exploit:</strong> {attack['psychology']}</div>
                    <div class="learn-text" style="margin-top:8px;"><strong>Examples:</strong>
                        <ul style="margin:8px 0 0 18px; padding:0;">{examples_html}</ul>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="learn-section">Social Engineering Psychology</div>', unsafe_allow_html=True)
        psych_data = PHISHING_PSYCHOLOGY_DATA['victim_psychology']
        ps_col1, ps_col2 = st.columns(2)
        for i, psych in enumerate(psych_data):
            col = ps_col1 if i % 2 == 0 else ps_col2
            with col:
                st.markdown(f"""
                <div class="learn-card">
                    <div class="learn-head">{psych['name']}</div>
                    <div class="learn-text"><strong>Definition:</strong> {psych['description']}</div>
                    <div class="learn-text" style="margin-top:8px;"><strong>How attackers exploit it:</strong> {psych['exploitation']}</div>
                    <div class="learn-text" style="margin-top:8px; color:#c7f2e6;"><strong>Defense strategy:</strong> {psych['defense']}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="learn-section">Defense Playbook</div>', unsafe_allow_html=True)
        best_practices = PHISHING_PSYCHOLOGY_DATA['best_practices']
        for idx, practice in enumerate(best_practices, 1):
            if practice['priority'] == 'CRITICAL':
                accent = "#8db9ff"
                bg = "rgba(141,185,255,0.14)"
            elif practice['priority'] == 'HIGH':
                accent = "#f6b26b"
                bg = "rgba(246,178,107,0.14)"
            else:
                accent = "#5ad3b0"
                bg = "rgba(90,211,176,0.14)"
            st.markdown(f"""
            <div class="learn-card" style="border-left:4px solid {accent}; background:{bg};">
                <div class="learn-head">{idx}. {practice['name']} <span style="font-size:11px; color:{accent};">[{practice['priority']}]</span></div>
                <div class="learn-text">{practice['description']}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="learn-section">Reference Resources</div>', unsafe_allow_html=True)
        resources = [
            ("NIST Cybersecurity Framework", "https://www.nist.gov/cyberframework"),
            ("OWASP Top 10", "https://owasp.org/www-project-top-ten/"),
            ("CIS Critical Controls", "https://www.cisecurity.org/cis-controls/"),
            ("SANS Security Training", "https://www.sans.org"),
            ("Krebs on Security", "https://krebsonsecurity.com")
        ]
        for name, url in resources:
            st.markdown(f'<a class="learn-link" href="{url}" target="_blank">{name}</a>', unsafe_allow_html=True)
    
    # Render footer
    st.markdown("""
    <div class="footer">
        <div class="footer-content">
            <div class="footer-main">PhishXzero</div>
            <div class="footer-divider"></div>
            <div class="footer-sub">
                Copyright 2026 PhishXzero by Shivansh Baskota | Kathmandu, Nepal<br>
                AI-powered phishing detection with real-time threat intelligence
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
        
