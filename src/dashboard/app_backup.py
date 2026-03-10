import streamlit as st
import json
import pandas as pd

st.set_page_config(page_title="PVSS Dashboard", layout="wide")
st.title("🔍 Point Vulnerability System Security (PVSS)")
st.markdown("Top point vulnerabilities based on PVS score")

# Load scored data
@st.cache_data
def load_data():
    with open("data/scored/scored_vulns.json", "r") as f:
        data = json.load(f)
    return data

data = load_data()
df = pd.DataFrame(data)

# Display top 10
st.subheader("🏆 Point Vulnerability Leaderboard")
top10 = df.head(10)
st.dataframe(top10[['cve_id', 'name', 'asset_ip', 'cvss_score', 'pvs', 'asset_role', 'exploit_multiplier']])

# Show details for selected vulnerability
st.subheader("🔎 Vulnerability Details")
selected = st.selectbox("Choose a CVE to inspect", df['cve_id'].tolist())
vuln = df[df['cve_id'] == selected].iloc[0]
st.json(vuln.to_dict())

# Add a bar chart of top PVS scores
st.subheader("📊 Top 20 PVS Scores")
chart_data = df.head(20)[['cve_id', 'pvs']].set_index('cve_id')
st.bar_chart(chart_data)