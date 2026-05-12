from virus_total_checker import check_ip_virustotal
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import requests
from logs_reader import read_windows_logs
from ai_model import SIEM_AI_Model

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="AL-AYN AL-SAHIRA SIEM",
    page_icon="👁",
    layout="wide"
)

# =========================================================
# CUSTOM CSS (تصحيح وإغلاق الـ DIVs لضمان استقرار التصميم)
# =========================================================
st.markdown("""
<style>
.stApp { background: linear-gradient(135deg, #0a0014, #120018, #1f0033); color: white; }
section[data-testid="stSidebar"] { background: rgba(15, 0, 30, 0.95); border-right: 2px solid #ff4dd2; }
.main-title { font-size: 50px; font-weight: bold; color: #ff4dd2; text-align: center; text-shadow: 0 0 15px #ff4dd2; padding: 20px; }
.sub-title { text-align: center; color: #00ffe5; font-size: 20px; margin-bottom: 30px; text-shadow: 0 0 10px #00ffe5; }
.metric-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(0,255,229,0.3); padding: 25px; border-radius: 20px; text-align: center; transition: 0.4s; }
.metric-card:hover { transform: translateY(-5px); border: 1px solid #ff4dd2; box-shadow: 0 0 30px rgba(255,77,210,0.5); }
.login-box { background: rgba(255,255,255,0.05); padding: 40px; border-radius: 25px; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(10px); }
</style>
""", unsafe_allow_html=True)

# =========================================================
# LOGIN SYSTEM
# =========================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown('<div class="login-box">', unsafe_allow_html=True)
        st.markdown('<div class="main-title">👁 AL-AYN AL-SAHIRA</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-title">AI POWERED CYBER SECURITY SIEM</div>', unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("LOGIN"):
            if username == "admin" and password == "1234":
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("ACCESS DENIED")
        st.markdown('</div>', unsafe_allow_html=True) # تم إغلاق الـ div هنا بشكل صحيح

# =========================================================
# MAIN DASHBOARD
# =========================================================
else:
    ai_model = SIEM_AI_Model()
    ai_model.train(pd.DataFrame({"Event ID": [4624, 4625, 4624, 4771, 4625]}))

    st.sidebar.title("🛡 SIEM MENU")
    page = st.sidebar.selectbox("Choose Page", ["Dashboard", "Windows Logs"])

    if page == "Dashboard":
        st.markdown('<div class="main-title">👁 AL-AYN AL-SAHIRA SIEM</div>', unsafe_allow_html=True)
        
        # جلب البيانات
        logs_df = read_windows_logs("System", 50) # القراءة من Sysmon أو System

        if not logs_df.empty:
            # التحسين الأمني لفحص VirusTotal لمنع التعليق
            ip_column = next((col for col in logs_df.columns if "ip" in col.lower()), None)
            
            if ip_column:
                with st.spinner('🔍 Analyzing IPs with Threat Intel...'):
                    # استخدام الـ Lambda المطور لتجنب أخطاء القيم الفارغة
                    logs_df["VT_Result"] = logs_df[ip_column].apply(lambda ip: check_ip_virustotal(ip) if pd.notna(ip) else "No IP")
            else:
                logs_df["VT_Result"] = "No IP Found"

            # تشغيل الـ AI
            logs_df["AI_Result"] = ai_model.predict(logs_df)
            # --- عرض الإحصائيات (Metrics) ---
            vt_malicious = len(logs_df[logs_df["VT_Result"] == "⚠️ Malicious IP"])
            ai_threats = len(logs_df[logs_df["AI_Result"] == "Threat"])
            
            c1, c2, c3 = st.columns(3)
            with c1: st.markdown(f'<div class="metric-card"><h3>{len(logs_df)}</h3>TOTAL LOGS</div>', unsafe_allow_html=True)
            with c2: st.markdown(f'<div class="metric-card"><h3 style="color:#ff4d4d;">{vt_malicious}</h3>VT ALERTS</div>', unsafe_allow_html=True)
            with c3: st.markdown(f'<div class="metric-card"><h3>{ai_threats}</h3>AI THREATS</div>', unsafe_allow_html=True)

            # --- الجداول ---
            st.write("---")
            st.subheader("📑 All Security Activity")
            st.dataframe(logs_df, use_container_width=True)

            # 🔥 إضافة فلتر التهديدات فقط (الطلب الجبار)
            st.subheader("🚨 Critical Threats Only")
            threats_only = logs_df[(logs_df["AI_Result"] == "Threat") | (logs_df["VT_Result"] == "⚠️ Malicious IP")]
            if not threats_only.empty:
                st.dataframe(threats_only, use_container_width=True)
                st.toast("🚨 Detected Critical Threats!", icon="🔥")
            else:
                st.success("No critical threats detected in current logs.")

    elif page == "Windows Logs":
        st.header("🖥 Live Windows Security Logs")
        st.dataframe(read_windows_logs("Security", 100), use_container_width=True)