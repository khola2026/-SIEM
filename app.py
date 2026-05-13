import streamlit as st
import pandas as pd
import requests
import openai
import plotly.express as px  
from logs_reader import read_windows_logs
from ai_model import SIEM_AI_Model

# =========================================================
# 1. إعدادات التصميم الاحترافي "المتوهج" (Cyber Glow UI)
# =========================================================
st.set_page_config(page_title="SIM-Cyber: Al-Ayn Al-Sahira", page_icon="👁", layout="wide")

st.markdown("""
<style>
    .stApp { background: #05000a; color: #e0e0e0; }
    .neon-title { 
        font-size: 55px; font-weight: bold; color: #ff4dd2; 
        text-align: center; text-shadow: 0 0 15px #ff4dd2, 0 0 30px #ff4dd2;
        padding: 20px; font-family: 'Courier New', monospace;
    }
    .glow-box {
        background: rgba(255, 255, 255, 0.05); border: 2px solid #00ffe5; border-radius: 15px;
        padding: 20px; text-align: center; box-shadow: 0 0 10px #00ffe5; transition: 0.5s ease;
    }
    .glow-box:hover {
        transform: translateY(-5px); box-shadow: 0 0 30px #00ffe5, 0 0 50px #00ffe5;
        background: rgba(0, 255, 229, 0.1);
    }
    .login-box {
        max-width: 400px; margin: auto; padding: 40px;
        border: 3px solid #bd00ff; border-radius: 20px;
        box-shadow: 0 0 25px #bd00ff; background: rgba(10, 0, 20, 0.95);
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# =========================================================
# 2. وظائف الاستخبارات والذكاء الاصطناعي (تم التحديث)
# =========================================================

# التوثيق: استخدام المفتاح الذي أثبت نجاحه في الاختبار
VT_API_KEY = "feb3f613119d49229576bc534f9ddfab7519b934facd15dd1bbe6b785897d62f"

def check_ip_virustotal(ip):
    """دالة فحص الـ IP عبر VirusTotal مع استثناء العناوين المحلية"""
    if ip in ["127.0.0.1", "::1", "0.0.0.0", "Localhost"]:
        return "Safe"
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=2)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            if stats['malicious'] > 0:
                return "⚠️ Malicious IP"
        return "Safe"
    except:
        return "Safe"

def get_llm_recommendation(threat_details):
    """ربط مع ChatGPT لتحليل التهديد"""
    try:
        openai.api_key = "YOUR_OPENAI_API_KEY" 
        prompt = f"بصفتك خبير أمن سيبراني، حلل التهديد التالي وقدم نصيحة تقنية قصيرة: {threat_details}"
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "أنت خبير SIEM."},
                      {"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception:
        return "⚠️ التوصية: سلوك مشبوه، يرجى عزل الجهاز ومراجعة السجلات."

def save_to_backend(event_id, ip, status):
    """إرسال البيانات إلى FastAPI"""
    try:
        payload = {"event_id": int(event_id), "source": ip, "message": f"Alert: {status}"}
        requests.post("http://127.0.0.1:8000/logs", json=payload, timeout=0.5)
    except: pass

# =========================================================
# 3. نظام تسجيل الدخول (Identity Access)
# =========================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.markdown('<br><br>', unsafe_allow_html=True)
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown('<h2 style="color:#bd00ff;">SYSTEM ACCESS</h2>', unsafe_allow_html=True)
    user = st.text_input("Identity")
    pw = st.text_input("Security Key", type="password")
    if st.button("INITIATE LOGIN"):
        if user == "admin" and pw == "cyber2026": 
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("ACCESS DENIED")
    st.markdown('</div>', unsafe_allow_html=True)
    # =========================================================
# 4. لوحة التحكم المتكاملة (SIM-Cyber Dashboard)
# =========================================================
else:
    ai_engine = SIEM_AI_Model()
    ai_engine.train(pd.DataFrame({"Event ID": [4624, 4625, 4624, 4771, 4625]}))
    
    st.sidebar.markdown("<h2 style='color:#ff4dd2;'>🛡 SIM-Cyber OPS</h2>", unsafe_allow_html=True)
    choice = st.sidebar.selectbox("Navigate", ["Live Dashboard", "History Archive"])

    if choice == "Live Dashboard":
        st.markdown('<div class="neon-title">👁 AL-AYN AL-SAHIRA SIEM</div>', unsafe_allow_html=True)
        
        logs_df = read_windows_logs("System", 50)

        if not logs_df.empty:
            with st.spinner('🚀 Analyzing Cyber Threats...'):
                # التوثيق: هنا يتم الفحص الحقيقي لكل IP
                logs_df["VT_Status"] = logs_df["Source IP"].apply(check_ip_virustotal)
                logs_df["AI_Status"] = ai_engine.predict(logs_df)

            # صناديق الإحصائيات (Metrics)
            c1, c2, c3 = st.columns(3)
            with c1: st.markdown(f'<div class="glow-box"><h2 style="color:#00ffe5;">{len(logs_df)}</h2>LOGS</div>', unsafe_allow_html=True)
            with c2: st.markdown(f'<div class="glow-box" style="border-color:#bd00ff;"><h2 style="color:#bd00ff;">{len(logs_df[logs_df["AI_Status"]=="Threat"])}</h2>AI THREATS</div>', unsafe_allow_html=True)
            # التوثيق: المربع الثالث الآن يقرأ من VT_Status الحقيقية
            with c3: st.markdown(f'<div class="glow-box" style="border-color:#ff4d4d;"><h2 style="color:#ff4d4d;">{len(logs_df[logs_df["VT_Status"]=="⚠️ Malicious IP"])}</h2>VT ALERTS</div>', unsafe_allow_html=True)

            # الرسوم البيانية (Charts)
            st.write("---")
            col_chart, col_data = st.columns([1, 1])
            with col_chart:
                st.subheader("📊 Threat Distribution")
                # دمج نتائج AI و VT في الرسم البياني
                threat_counts = logs_df['AI_Status'].value_counts().reset_index()
                threat_counts.columns = ['Status', 'Count']
                fig = px.pie(threat_counts, values='Count', names='Status', hole=0.4,
                             color_discrete_sequence=['#00ffe5', '#ff4dd2'])
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="#eee")
                st.plotly_chart(fig, use_container_width=True)
            
            with col_data:
                st.subheader("📑 Stream Preview")
                st.dataframe(logs_df[["Event ID", "Source IP", "AI_Status", "VT_Status"]].head(10), use_container_width=True)

            # تحليل التهديدات الحرجة
            critical = logs_df[(logs_df["AI_Status"] == "Threat") | (logs_df["VT_Status"] == "⚠️ Malicious IP")]
            if not critical.empty:
                st.divider()
                st.markdown("<h3 style='color:#ff4d4d;'>🚨 AI Intelligence Analysis</h3>", unsafe_allow_html=True)
                for _, row in critical.iterrows():
                    rec = get_llm_recommendation(f"IP: {row['Source IP']}, AI: {row['AI_Status']}, VT: {row['VT_Status']}")
                    with st.expander(f"🔴 Action Plan for: {row['Source IP']}"):
                        st.info(rec)
                        save_to_backend(row["Event ID"], row["Source IP"], row["AI_Status"])

    elif choice == "History Archive":
        st.markdown('<div class="neon-title">📜 SECURE ARCHIVE</div>', unsafe_allow_html=True)
        try:
            response = requests.get("http://127.0.0.1:8000/logs")
            if response.status_code == 200:
                st.dataframe(pd.DataFrame(response.json()), use_container_width=True)
        except: st.warning("⚠️ Backend Offline: Start FastAPI server.")

    st.markdown("<hr><center><div style='color: #666; font-size: 14px;'>AL-AYN AL-SAHIRA SIEM © 2026</div></center>", unsafe_allow_html=True)
