"""
Enhanced Streamlit Dashboard with Advanced Visualization & Reporting
"""

import streamlit as st
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import defaultdict

# Import export and reporting modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from exports.exporters import export_results
from exports.pdf_reporter import generate_pdf_report

# Page configuration
st.set_page_config(
    page_title="RedTeam Enhanced Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .vulnerability-badge {
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-critical { background-color: #dc3545; color: white; }
    .badge-high { background-color: #fd7e14; color: white; }
    .badge-medium { background-color: #ffc107; color: black; }
    .badge-low { background-color: #17a2b8; color: white; }
    </style>
""", unsafe_allow_html=True)

# File paths
RESULTS_PATH = "data/results.jsonl"
SCORES_PATH = "data/score_report.json"
ATTACKS_PATH = "data/sample_attack_cases.json"

# Helper functions
@st.cache_data(ttl=60)
def load_results(path):
    """Load results from JSONL file."""
    if not os.path.exists(path):
        return []
    items = []
    with open(path, "r", encoding="utf8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception as e:
                st.warning(f"Could not parse line {i}: {e}")
    return items

@st.cache_data(ttl=60)
def load_scores(path):
    """Load scores from JSON file."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "scores" in data:
                return data["scores"]
            return data if isinstance(data, list) else []
    except Exception:
        return []

@st.cache_data(ttl=60)
def load_attacks(path):
    """Load attack cases from JSON file."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return []

def get_severity_level(score):
    """Convert severity score to level."""
    if score >= 0.85:
        return "Critical"
    elif score >= 0.6:
        return "High"
    elif score >= 0.3:
        return "Medium"
    else:
        return "Low"

def get_severity_color(level):
    """Get color for severity level."""
    colors = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8"
    }
    return colors.get(level, "#6c757d")

def parse_timestamp(ts_str):
    """Parse timestamp string to datetime."""
    try:
        # Try ISO format
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        # Try alternative formats
        try:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except:
            return None

def filter_results(results, scores, filters):
    """Filter results based on user selections."""
    score_map = {s.get("attack_id"): s for s in scores}

    filtered = []
    for r in results:
        aid = r.get("attack_id", "")
        score = score_map.get(aid, {})

        # Filter by severity
        if filters['severity'] != "All":
            severity_score = score.get('severity_score', 0)
            severity_level = get_severity_level(severity_score)
            if severity_level != filters['severity']:
                continue

        # Filter by vulnerability status
        if filters['vuln_status'] != "All":
            is_vulnerable = score.get('vulnerable', False)
            if filters['vuln_status'] == "Vulnerable" and not is_vulnerable:
                continue
            if filters['vuln_status'] == "Safe" and is_vulnerable:
                continue

        # Filter by tags
        if filters['tags'] and "All" not in filters['tags']:
            score_tags = score.get('tags', [])
            if not any(tag in score_tags for tag in filters['tags']):
                continue

        # Filter by date range
        if filters['date_range'] and r.get('timestamp'):
            ts = parse_timestamp(r.get('timestamp'))
            if ts:
                if not (filters['date_range'][0] <= ts.date() <= filters['date_range'][1]):
                    continue

        filtered.append((r, score))

    return filtered

# Load data
results = load_results(RESULTS_PATH)
scores = load_scores(SCORES_PATH)
attacks = load_attacks(ATTACKS_PATH)
score_map = {s.get("attack_id"): s for s in scores}

# Sidebar
st.sidebar.title("RedTeam Dashboard")
st.sidebar.markdown("---")

# Navigation
page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Attack Explorer", "Time Trends", "Model Comparison", "Heatmap Analysis", "Export & Reports"]
)

st.sidebar.markdown("---")

# Filters (available on all pages)
st.sidebar.header("Filters")

# Get all unique tags
all_tags = set()
for score in scores:
    all_tags.update(score.get('tags', []))
all_tags = sorted(list(all_tags))

# Filter controls
severity_filter = st.sidebar.selectbox(
    "Severity Level",
    ["All", "Critical", "High", "Medium", "Low"]
)

vuln_status_filter = st.sidebar.selectbox(
    "Vulnerability Status",
    ["All", "Vulnerable", "Safe"]
)

tags_filter = st.sidebar.multiselect(
    "Tags",
    ["All"] + all_tags,
    default=["All"]
)

# Date range filter
use_date_filter = st.sidebar.checkbox("Filter by Date Range")
date_range = None
if use_date_filter:
    col1, col2 = st.sidebar.columns(2)
    with col1:
        start_date = st.date_input("From", datetime.now() - timedelta(days=30))
    with col2:
        end_date = st.date_input("To", datetime.now())
    date_range = (start_date, end_date)

# Collect filters
filters = {
    'severity': severity_filter,
    'vuln_status': vuln_status_filter,
    'tags': tags_filter,
    'date_range': date_range
}

# Apply filters
filtered_data = filter_results(results, scores, filters)

# Refresh button
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()

# Main content based on page selection
if page == "Overview":
    st.title("🎯 Security Assessment Overview")

    # Calculate statistics
    total_attacks = len(results)
    vulnerable_count = sum(1 for s in scores if s.get('vulnerable', False))
    safe_count = total_attacks - vulnerable_count

    if scores:
        avg_severity = sum(s.get('severity_score', 0) for s in scores if s.get('vulnerable', False)) / max(vulnerable_count, 1)
    else:
        avg_severity = 0

    # Display metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Attacks", total_attacks)
    with col2:
        st.metric("Vulnerabilities Found", vulnerable_count)
    with col3:
        vuln_rate = (vulnerable_count / max(total_attacks, 1)) * 100
        st.metric("Vulnerability Rate", f"{vuln_rate:.1f}%")
    with col4:
        st.metric("Avg Severity", f"{avg_severity:.2f}")

    st.markdown("---")

    # Severity distribution
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for score in scores:
            if score.get('vulnerable', False):
                level = get_severity_level(score.get('severity_score', 0))
                severity_counts[level] += 1

        fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Vulnerabilities by Severity",
            color_discrete_map={
                "Critical": "#dc3545",
                "High": "#fd7e14",
                "Medium": "#ffc107",
                "Low": "#17a2b8"
            }
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Vulnerability Types")
        vuln_types = defaultdict(int)
        for score in scores:
            if score.get('vulnerable', False):
                for reason in score.get('vulnerability_reasons', []):
                    vuln_types[reason] += 1

        if vuln_types:
            fig = px.bar(
                x=list(vuln_types.keys()),
                y=list(vuln_types.values()),
                title="Vulnerability Types Distribution",
                labels={'x': 'Vulnerability Type', 'y': 'Count'}
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No vulnerabilities detected")

    # Recent vulnerabilities
    st.markdown("---")
    st.subheader("Recent Critical Vulnerabilities")

    critical_vulns = [
        s for s in scores
        if s.get('vulnerable', False) and s.get('severity_score', 0) >= 0.85
    ]
    critical_vulns.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    if critical_vulns[:5]:
        for vuln in critical_vulns[:5]:
            with st.expander(f"🚨 {vuln.get('attack_id')} - Severity: {vuln.get('severity_score', 0):.2f}"):
                st.write(f"**Vulnerability Reasons:** {', '.join(vuln.get('vulnerability_reasons', []))}")
                st.write(f"**Evidence Count:** {vuln.get('evidence_count', 0)}")
                st.write(f"**Tags:** {', '.join(vuln.get('tags', []))}")
                st.write(f"**Notes:** {vuln.get('notes', '')}")
    else:
        st.success("No critical vulnerabilities found!")

elif page == "Attack Explorer":
    st.title("🔍 Interactive Attack Explorer")

    st.write(f"Showing {len(filtered_data)} of {len(results)} attacks")

    # Results table
    if filtered_data:
        table_data = []
        for r, score in filtered_data:
            severity_score = score.get('severity_score', 0)
            severity_level = get_severity_level(severity_score)

            table_data.append({
                "Attack ID": r.get("attack_id", ""),
                "Prompt Preview": (r.get("prompt") or "")[:100].replace("\n", " "),
                "Vulnerable": "✅" if score.get('vulnerable', False) else "❌",
                "Severity": severity_level,
                "Score": f"{severity_score:.2f}",
                "Tags": ", ".join(score.get('tags', []))
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)

        # Detailed view
        st.markdown("---")
        st.subheader("Detailed Attack View")

        selected_attack = st.selectbox(
            "Select Attack to View Details",
            options=[r.get("attack_id", "") for r, _ in filtered_data]
        )

        if selected_attack:
            # Find the selected attack
            for r, score in filtered_data:
                if r.get("attack_id") == selected_attack:
                    col1, col2 = st.columns([2, 1])

                    with col1:
                        st.subheader("Prompt")
                        st.code(r.get("prompt", ""), language="text")

                        st.subheader("Response")
                        st.text_area("Model Response", r.get("response", ""), height=200, key=f"response_{selected_attack}")

                    with col2:
                        st.subheader("Analysis")

                        if score.get('vulnerable', False):
                            st.error(f"🚨 VULNERABLE")
                        else:
                            st.success(f"✅ SAFE")

                        st.metric("Severity Score", f"{score.get('severity_score', 0):.2f}")
                        st.write(f"**Level:** {get_severity_level(score.get('severity_score', 0))}")
                        st.write(f"**Evidence Count:** {score.get('evidence_count', 0)}")
                        st.write(f"**Tags:** {', '.join(score.get('tags', []))}")

                        if score.get('vulnerability_reasons'):
                            st.write("**Vulnerability Types:**")
                            for reason in score.get('vulnerability_reasons', []):
                                st.write(f"- {reason}")

                        st.write("**Timestamp:**", r.get('timestamp', 'N/A'))

                    st.markdown("---")
                    st.subheader("Evidence")
                    if score.get('evidence'):
                        for i, evidence in enumerate(score.get('evidence', []), 1):
                            st.write(f"{i}. {evidence}")

                    if score.get('notes'):
                        st.subheader("Notes")
                        st.info(score.get('notes'))

                    break
    else:
        st.info("No attacks match the current filters")

elif page == "Time Trends":
    st.title("📈 Attack Success Trends")

    # Parse timestamps and aggregate by date
    if results and scores:
        time_data = []
        for r in results:
            ts_str = r.get('timestamp')
            if ts_str:
                ts = parse_timestamp(ts_str)
                if ts:
                    aid = r.get('attack_id')
                    score = score_map.get(aid, {})
                    time_data.append({
                        'date': ts.date(),
                        'datetime': ts,
                        'vulnerable': score.get('vulnerable', False),
                        'severity': score.get('severity_score', 0),
                        'attack_id': aid
                    })

        if time_data:
            df = pd.DataFrame(time_data)

            # Vulnerability rate over time
            st.subheader("Vulnerability Rate Over Time")
            daily_stats = df.groupby('date').agg({
                'vulnerable': ['sum', 'count']
            }).reset_index()
            daily_stats.columns = ['date', 'vulnerable_count', 'total_count']
            daily_stats['vulnerability_rate'] = (daily_stats['vulnerable_count'] / daily_stats['total_count']) * 100

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['vulnerability_rate'],
                mode='lines+markers',
                name='Vulnerability Rate',
                line=dict(color='#dc3545', width=2)
            ))
            fig.update_layout(
                title="Daily Vulnerability Rate",
                xaxis_title="Date",
                yaxis_title="Vulnerability Rate (%)",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)

            # Severity trend
            st.subheader("Average Severity Over Time")
            vulnerable_df = df[df['vulnerable'] == True]
            if not vulnerable_df.empty:
                severity_trend = vulnerable_df.groupby('date')['severity'].mean().reset_index()

                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=severity_trend['date'],
                    y=severity_trend['severity'],
                    mode='lines+markers',
                    name='Avg Severity',
                    line=dict(color='#fd7e14', width=2),
                    fill='tozeroy'
                ))
                fig.update_layout(
                    title="Average Severity Score Over Time",
                    xaxis_title="Date",
                    yaxis_title="Severity Score",
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No vulnerable attacks to show severity trends")

            # Attack volume
            st.subheader("Attack Volume")
            attack_volume = df.groupby('date').size().reset_index(name='count')

            fig = px.bar(
                attack_volume,
                x='date',
                y='count',
                title="Daily Attack Volume"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No timestamp data available for trend analysis")
    else:
        st.info("No data available for trend analysis")

elif page == "Model Comparison":
    st.title("⚖️ Model Comparison View")

    st.info("Model comparison requires results from multiple models. Run attacks against different models to see comparisons.")

    # Extract model information from results
    models = set()
    for r in results:
        model_meta = r.get('model_meta', {})
        provider = model_meta.get('provider', model_meta.get('mock', 'unknown'))
        if provider != 'unknown' and provider != False:
            models.add(str(provider))

    if len(models) >= 2:
        st.subheader("Model Performance Comparison")

        # Compare models
        model_stats = {}
        for model in models:
            model_results = [
                r for r in results
                if str(r.get('model_meta', {}).get('provider', r.get('model_meta', {}).get('mock', ''))) == model
            ]

            vulnerable = 0
            total = len(model_results)
            avg_severity = 0

            for r in model_results:
                aid = r.get('attack_id')
                score = score_map.get(aid, {})
                if score.get('vulnerable', False):
                    vulnerable += 1
                    avg_severity += score.get('severity_score', 0)

            if vulnerable > 0:
                avg_severity /= vulnerable

            model_stats[model] = {
                'total': total,
                'vulnerable': vulnerable,
                'rate': (vulnerable / max(total, 1)) * 100,
                'avg_severity': avg_severity
            }

        # Display comparison
        comparison_df = pd.DataFrame(model_stats).T
        st.dataframe(comparison_df)

        # Charts
        col1, col2 = st.columns(2)

        with col1:
            fig = px.bar(
                x=list(model_stats.keys()),
                y=[stats['rate'] for stats in model_stats.values()],
                title="Vulnerability Rate by Model",
                labels={'x': 'Model', 'y': 'Vulnerability Rate (%)'}
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = px.bar(
                x=list(model_stats.keys()),
                y=[stats['avg_severity'] for stats in model_stats.values()],
                title="Average Severity by Model",
                labels={'x': 'Model', 'y': 'Average Severity Score'}
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning(f"Found {len(models)} model(s). Run attacks against multiple models to enable comparison.")

elif page == "Heatmap Analysis":
    st.title("🔥 Attack Type vs Model Vulnerability Heatmap")

    # Create heatmap data
    attack_tags = set()
    for score in scores:
        attack_tags.update(score.get('tags', []))
    attack_tags = sorted(list(attack_tags))

    models = set()
    for r in results:
        model_meta = r.get('model_meta', {})
        provider = model_meta.get('provider', 'mock' if model_meta.get('mock') else 'unknown')
        if provider and provider != 'unknown':
            models.add(str(provider))
    models = sorted(list(models))

    if attack_tags and models:
        # Build heatmap matrix
        heatmap_data = []
        for tag in attack_tags:
            row = []
            for model in models:
                # Count vulnerable attacks for this tag+model combination
                vulnerable_count = 0
                total_count = 0

                for r in results:
                    r_model = str(r.get('model_meta', {}).get('provider', 'mock' if r.get('model_meta', {}).get('mock') else ''))
                    if r_model != model:
                        continue

                    aid = r.get('attack_id')
                    score = score_map.get(aid, {})
                    if tag in score.get('tags', []):
                        total_count += 1
                        if score.get('vulnerable', False):
                            vulnerable_count += 1

                # Calculate rate
                rate = (vulnerable_count / max(total_count, 1)) * 100 if total_count > 0 else 0
                row.append(rate)
            heatmap_data.append(row)

        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=models,
            y=attack_tags,
            colorscale='Reds',
            text=[[f"{val:.1f}%" for val in row] for row in heatmap_data],
            texttemplate='%{text}',
            textfont={"size": 10},
            colorbar=dict(title="Vulnerability<br>Rate (%)")
        ))

        fig.update_layout(
            title="Attack Type vs Model Vulnerability Matrix",
            xaxis_title="Model",
            yaxis_title="Attack Type",
            height=max(400, len(attack_tags) * 40)
        )

        st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.subheader("Interpretation")
        st.write("""
        - **Darker colors** indicate higher vulnerability rates for that attack type and model combination
        - **Lighter colors** indicate lower vulnerability rates
        - Use this to identify which models are most vulnerable to specific attack types
        """)
    else:
        st.warning("Insufficient data for heatmap analysis. Run attacks against multiple models with various tags.")

elif page == "Export & Reports":
    st.title("📊 Export & Reports")

    st.subheader("Export Data")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📄 Export to CSV"):
            try:
                # Combine results and scores
                combined_data = []
                for r in results:
                    aid = r.get('attack_id')
                    score = score_map.get(aid, {})
                    combined_data.append({
                        **r,
                        **score
                    })

                path = export_results(combined_data, format='csv')
                st.success(f"Exported to {path}")
            except Exception as e:
                st.error(f"Export failed: {e}")

    with col2:
        if st.button("📋 Export to JSON"):
            try:
                combined_data = []
                for r in results:
                    aid = r.get('attack_id')
                    score = score_map.get(aid, {})
                    combined_data.append({
                        **r,
                        **score
                    })

                path = export_results(combined_data, format='json')
                st.success(f"Exported to {path}")
            except Exception as e:
                st.error(f"Export failed: {e}")

    with col3:
        if st.button("🔍 Export to SARIF"):
            try:
                path = export_results(scores, format='sarif')
                st.success(f"Exported to {path}")
                st.info("SARIF format is compatible with GitHub Advanced Security and other security tools")
            except Exception as e:
                st.error(f"Export failed: {e}")

    st.markdown("---")
    st.subheader("Generate PDF Report")

    report_name = st.text_input("Report Filename", "security_report")

    if st.button("📑 Generate Executive Summary (PDF/HTML)"):
        try:
            metadata = {
                "models_tested": list(set(str(r.get('model_meta', {}).get('provider', 'mock')) for r in results)),
                "test_date": datetime.now().strftime("%Y-%m-%d"),
                "total_attacks": len(results),
                "vulnerabilities_found": sum(1 for s in scores if s.get('vulnerable', False))
            }

            path = generate_pdf_report(results, scores, metadata)
            st.success(f"Report generated: {path}")

            # Offer download
            if Path(path).exists():
                with open(path, 'rb') as f:
                    st.download_button(
                        label="⬇️ Download Report",
                        data=f,
                        file_name=Path(path).name,
                        mime="application/pdf" if path.endswith('.pdf') else "text/html"
                    )
        except Exception as e:
            st.error(f"Report generation failed: {e}")

    st.markdown("---")
    st.subheader("Attack Replay")

    st.write("Re-run historical attacks with updated models")

    if attacks:
        selected_attacks = st.multiselect(
            "Select Attacks to Replay",
            options=[a.get('attack_id') for a in attacks]
        )

        model_provider = st.selectbox(
            "Select Model",
            ["mock", "openai", "gemini"]
        )

        if st.button("🔄 Replay Selected Attacks"):
            if selected_attacks:
                st.info(f"Replaying {len(selected_attacks)} attacks against {model_provider}...")
                st.write("Run the following command:")
                st.code(f"python -m runner.cli --model={model_provider} --attacks-file=data/sample_attack_cases.json")
            else:
                st.warning("Please select at least one attack to replay")
    else:
        st.warning("No attack cases found")

# Footer
st.sidebar.markdown("---")
st.sidebar.info(f"Dashboard v2.0 | Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
