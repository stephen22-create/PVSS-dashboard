import streamlit as st
import pandas as pd
import json
import numpy as np
import requests
import os
from io import StringIO
from datetime import datetime
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

st.set_page_config(page_title="PVSS Dashboard", layout="wide")
st.title("🔍 Point Vulnerability System Security (PVSS)")
st.markdown("Threat‑informed, context‑aware vulnerability prioritization")

# ------------------------------
# Load scored data with fallback
# ------------------------------
@st.cache_data
def load_data():
    try:
        with open("data/scored/scored_vulns.json", "r") as f:
            data = json.load(f)
        return pd.DataFrame(data)
    except FileNotFoundError:
        # Generate a default synthetic dataset for demonstration
        st.warning("No data file found. Using synthetic demo data.")
        np.random.seed(42)  # for reproducibility
        n_vulns = 50
        cves = [f"CVE-2025-{i:04d}" for i in range(1000, 1000 + n_vulns)]
        asset_ips = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "10.0.0.51",
                     "172.16.1.10", "172.16.1.20"]
        asset_roles = ["domain_controller", "web_server", "database_server",
                       "workstation", "test_lab", "unknown"]
        exploit_multipliers = [1.0, 1.5, 2.0]
        data = []
        for i in range(n_vulns):
            ip = np.random.choice(asset_ips)
            role = np.random.choice(asset_roles)
            # ensure consistency: if asset_role is unknown, pick a random role
            if role == "unknown":
                role = np.random.choice(asset_roles[:-1])
            data.append({
                "cve_id": cves[i],
                "name": f"Vulnerability {i}",
                "asset_ip": ip,
                "asset_role": role,
                "cvss_score": round(np.random.uniform(5.0, 10.0), 1),
                "exploit_multiplier": np.random.choice(exploit_multipliers),
                "pvs": None,  # will compute below
                "first_seen": pd.Timestamp.now() - pd.Timedelta(days=np.random.randint(0, 365)),
                "status": np.random.choice(["Open", "In Progress", "Resolved"]),
                "in_kev": np.random.choice([True, False], p=[0.2, 0.8]),
                "solution": "Apply vendor patch",
                "description": "Sample vulnerability description"
            })
        df = pd.DataFrame(data)
        # Compute PVS based on formula (simplified for demo)
        # criticality factor (placeholder)
        criticality_map = {
            'domain_controller': 1.8,
            'web_server': 1.2,
            'database_server': 1.2,
            'workstation': 0.8,
            'test_lab': 0.4,
            'unknown': 1.0
        }
        df['asset_criticality'] = df['asset_role'].map(criticality_map).fillna(1.0)
        df['pvs'] = df['cvss_score'] * df['exploit_multiplier'] * df['asset_criticality']
        # Ensure first_seen is datetime
        df['first_seen'] = pd.to_datetime(df['first_seen'])
        return df

df = load_data()

# Add status column if not present (for remediation tracking)
if 'status' not in df.columns:
    df['status'] = 'Open'

# Ensure a date column exists (for trends) – already done, but double-check
if 'first_seen' not in df.columns:
    start = pd.Timestamp('2025-01-01')
    end = pd.Timestamp('2026-02-01')
    df['first_seen'] = pd.to_datetime(np.random.randint(start.value, end.value, size=len(df)))
    st.info("No 'first_seen' column found. Using randomly generated dates for trend demo.")
else:
    df['first_seen'] = pd.to_datetime(df['first_seen'])

# ------------------------------
# CISA KEV loader (local file with download fallback)
# ------------------------------
@st.cache_data(ttl=86400)
def get_kev_set():
    local_path = "data/threat_intel/kev.csv"
    # Try to read local file first
    if os.path.exists(local_path):
        try:
            kev_df = pd.read_csv(local_path)
            return set(kev_df['cveID'].tolist())
        except Exception as e:
            st.warning(f"Error reading local KEV file: {e}")
    
    # If local file not found or error, attempt download
    st.info("Local KEV file not found. Attempting to download from CISA (this may take a moment)...")
    try:
        url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        resp = requests.get(url, timeout=30)
        kev_df = pd.read_csv(StringIO(resp.text))
        # Save a local copy for next time
        os.makedirs("data/threat_intel", exist_ok=True)
        kev_df.to_csv(local_path, index=False)
        st.success("KEV catalog downloaded and saved locally.")
        return set(kev_df['cveID'].tolist())
    except Exception as e:
        st.warning(f"Could not fetch CISA KEV: {e}. Proceeding without KEV highlights.")
        return set()

kev_set = get_kev_set()
df['in_kev'] = df['cve_id'].apply(lambda x: x in kev_set)

# ------------------------------
# Attack graph function
# ------------------------------
def create_attack_graph(graph_df, pvs_threshold=0):
    """
    Generate an interactive network graph of assets and vulnerabilities.
    Only vulnerabilities with PVS >= pvs_threshold are included.
    """
    # Filter by PVS threshold
    filtered = graph_df[graph_df['pvs'] >= pvs_threshold].copy()
    if filtered.empty:
        return None

    # Create a pyvis network
    net = Network(height='600px', width='100%', bgcolor='#222222', font_color='white')

    # Define color maps
    asset_color_map = {
        'domain_controller': '#ff4d4d',  # red
        'pci_data': '#ff944d',            # orange
        'phi_data': '#ff944d',            # orange
        'database_server': '#ffaa00',      # gold
        'web_server': '#66b3ff',           # light blue
        'default': '#add8e6'               # default blue
    }
    exploit_color_map = {
        2.0: '#ff0000',    # red – active exploit
        1.5: '#ffa500',    # orange – PoC available
        1.0: '#00ff00'     # green – no known exploit
    }

    # Add asset nodes
    assets = filtered['asset_ip'].unique()
    for asset in assets:
        role = filtered[filtered['asset_ip'] == asset]['asset_role'].iloc[0]
        color = asset_color_map.get(role, asset_color_map['default'])
        net.add_node(asset, label=asset, color=color, title=f"Role: {role}", shape='box')

    # Add vulnerability nodes and edges
    for _, row in filtered.iterrows():
        vuln_id = f"{row['cve_id']} on {row['asset_ip']}"
        label = row['cve_id'][:15] + '...' if len(row['cve_id']) > 15 else row['cve_id']
        exploit = row['exploit_multiplier']
        color = exploit_color_map.get(exploit, '#888888')
        net.add_node(vuln_id, label=label, color=color, title=f"PVS: {row['pvs']:.2f}", shape='dot')
        net.add_edge(row['asset_ip'], vuln_id, value=row['pvs'], title=f"PVS: {row['pvs']:.2f}")

    # Set physics for better layout
    net.set_options("""
    var options = {
      "physics": {
        "enabled": true,
        "barnesHut": {
          "gravitationalConstant": -8000,
          "centralGravity": 0.3,
          "springLength": 95,
          "springConstant": 0.04,
          "damping": 0.09
        }
      }
    }
    """)
    return net

# ------------------------------
# Sidebar filters
# ------------------------------
st.sidebar.header("🔎 Filters")

# Asset role
asset_roles = ["All"] + sorted(df['asset_role'].dropna().unique().tolist())
selected_role = st.sidebar.selectbox("Asset Role", asset_roles)

# CVE multi‑select
cve_options = sorted(df['cve_id'].dropna().unique().tolist())
selected_cves = st.sidebar.multiselect("CVE ID(s)", cve_options)

# Exploit multiplier
exploit_map = {"All": None, "2.0 (Active)": 2.0, "1.5 (PoC)": 1.5, "1.0 (None)": 1.0}
selected_exploit_label = st.sidebar.radio("Exploit Status", list(exploit_map.keys()))
selected_exploit = exploit_map[selected_exploit_label]

# Asset IP
asset_ips = ["All"] + sorted(df['asset_ip'].dropna().unique().tolist())
selected_ip = st.sidebar.selectbox("Asset IP", asset_ips)

# Apply filters
filtered_df = df.copy()
if selected_role != "All":
    filtered_df = filtered_df[filtered_df['asset_role'] == selected_role]
if selected_cves:
    filtered_df = filtered_df[filtered_df['cve_id'].isin(selected_cves)]
if selected_exploit is not None:
    filtered_df = filtered_df[filtered_df['exploit_multiplier'] == selected_exploit]
if selected_ip != "All":
    filtered_df = filtered_df[filtered_df['asset_ip'] == selected_ip]

# Filter summary
st.sidebar.markdown(f"**Showing {len(filtered_df)} of {len(df)} vulnerabilities**")

# CSV export
st.sidebar.markdown("---")
csv = filtered_df.to_csv(index=False)
st.sidebar.download_button(
    label="📥 Download Filtered Data as CSV",
    data=csv,
    file_name=f"pvss_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv"
)

# ------------------------------
# Main dashboard with tabs (now 5 tabs)
# ------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏆 Leaderboard", "📌 Asset View", "📊 Analysis", "🛠️ Remediation", "🔗 Attack Graph"])

# ---------- Tab 1: Leaderboard ----------
with tab1:
    st.subheader("Top Point Vulnerabilities")
    st.dataframe(
        filtered_df[['cve_id', 'name', 'asset_ip', 'cvss_score', 'pvs', 'asset_role', 'exploit_multiplier']].head(20),
        use_container_width=True
    )

    st.subheader("🔎 Vulnerability Details")
    if not filtered_df.empty:
        selected_cve = st.selectbox("Choose a CVE to inspect", filtered_df['cve_id'].tolist())
        vuln = filtered_df[filtered_df['cve_id'] == selected_cve].iloc[0]
        st.json(vuln.to_dict())
    else:
        st.info("No vulnerabilities match the current filters.")

    st.subheader("📊 Top 20 PVS Scores")
    chart_data = filtered_df.head(20)[['cve_id', 'pvs']].set_index('cve_id')
    st.bar_chart(chart_data)

# ---------- Tab 2: Asset View ----------
with tab2:
    st.subheader("Asset Summary")
    asset_summary = filtered_df.groupby('asset_ip').agg(
        total_vulns=('cve_id', 'count'),
        avg_pvs=('pvs', 'mean'),
        max_pvs=('pvs', 'max'),
        critical_assets=('asset_role', lambda x: (x.isin(['domain_controller','pci_data','phi_data'])).any())
    ).reset_index()
    st.dataframe(asset_summary, use_container_width=True)

    st.subheader("🔍 Asset Drill‑down")
    if not filtered_df.empty:
        selected_asset = st.selectbox("Select asset IP", filtered_df['asset_ip'].unique())
        asset_vulns = filtered_df[filtered_df['asset_ip'] == selected_asset][
            ['cve_id', 'cvss_score', 'pvs', 'asset_role', 'exploit_multiplier']
        ]
        st.dataframe(asset_vulns, use_container_width=True)
    else:
        st.info("No data for the selected asset.")

# ---------- Tab 3: Analysis ----------
with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Top 10 by CVSS**")
        top_cvss = filtered_df.nlargest(10, 'cvss_score')[['cve_id', 'asset_ip', 'cvss_score']]
        st.dataframe(top_cvss, use_container_width=True)
    with col2:
        st.markdown("**Top 10 by PVS**")
        top_pvs = filtered_df.nlargest(10, 'pvs')[['cve_id', 'asset_ip', 'pvs']]
        st.dataframe(top_pvs, use_container_width=True)

    st.markdown("---")
    st.subheader("📈 Historical Trends")
    if not filtered_df.empty:
        weekly_counts = filtered_df.resample('W', on='first_seen').size().reset_index(name='count')
        st.line_chart(weekly_counts.set_index('first_seen')['count'])

        weekly_avg_pvs = filtered_df.resample('W', on='first_seen')['pvs'].mean().reset_index(name='avg_pvs')
        st.line_chart(weekly_avg_pvs.set_index('first_seen')['avg_pvs'])
    else:
        st.info("No data to display trends.")

    st.markdown("---")
    st.subheader("🔥 CISA KEV Highlights")
    kev_highlights = filtered_df[filtered_df['in_kev']].nlargest(5, 'pvs')[['cve_id', 'asset_ip', 'pvs', 'asset_role']]
    if not kev_highlights.empty:
        st.dataframe(kev_highlights, use_container_width=True)
    else:
        st.write("No vulnerabilities from CISA KEV in the current dataset.")

# ---------- Tab 4: Remediation ----------
with tab4:
    st.subheader("🛠️ Remediation Tracking")
    st.markdown("Update the status of vulnerabilities below. Changes are saved to the JSON file.")

    display_cols = ['cve_id', 'name', 'asset_ip', 'pvs', 'asset_role', 'status']
    editable_df = filtered_df[display_cols].copy()

    edited_df = st.data_editor(
        editable_df,
        column_config={
            "status": st.column_config.SelectboxColumn(
                "Status",
                help="Remediation status",
                options=["Open", "In Progress", "Resolved"],
                required=True
            )
        },
        disabled=["cve_id", "name", "asset_ip", "pvs", "asset_role"],
        use_container_width=True,
        key="remediation_editor"
    )

    if st.button("💾 Save Status Updates"):
        for idx, row in edited_df.iterrows():
            mask = (df['cve_id'] == row['cve_id']) & (df['asset_ip'] == row['asset_ip'])
            if mask.any():
                df.loc[mask, 'status'] = row['status']
        df.to_json("data/scored/scored_vulns.json", orient="records", indent=2)
        st.success("Statuses saved successfully!")
        st.rerun()

# ---------- Tab 5: Attack Graph ----------
with tab5:
    st.subheader("🔗 Attack Path Visualisation")
    st.markdown("Interactive graph showing connections between assets and vulnerabilities.")

    if filtered_df.empty:
        st.warning("No data matches the current filters.")
    else:
        # Slider to filter by minimum PVS
        min_pvs = st.slider("Minimum PVS to display", 
                            min_value=0.0, 
                            max_value=float(filtered_df['pvs'].max()), 
                            value=20.0, 
                            step=5.0)

        if st.button("Generate Attack Graph"):
            with st.spinner("Building graph... (may take a moment for large datasets)"):
                net = create_attack_graph(filtered_df, pvs_threshold=min_pvs)
                if net is None:
                    st.info(f"No vulnerabilities with PVS >= {min_pvs}.")
                else:
                    # Save the graph to an HTML file
                    net.save_graph('attack_graph.html')
                    # Read and display the HTML
                    with open('attack_graph.html', 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    components.html(html_content, height=600)