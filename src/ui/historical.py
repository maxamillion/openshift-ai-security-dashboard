"""Historical tab for OpenShift AI Security Dashboard."""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from ..services.cve_analyzer import CVEAnalyzer
from ..database.connection import get_db_session
from ..database.models import Release


def render_historical_tab(release_id: int, analyzer: CVEAnalyzer):
    """Render the historical analysis tab."""
    try:
        st.subheader("📈 Historical Security Analysis")
        
        # Get available releases for comparison
        releases = get_available_releases()
        
        if len(releases) < 2:
            st.warning("⚠️ Historical analysis requires at least 2 releases. Please refresh data to load more releases.")
            return
        
        # Render controls
        analysis_type = render_historical_controls(releases, release_id)
        
        st.markdown("---")
        
        if analysis_type == "trends":
            render_security_trends(release_id, analyzer)
        elif analysis_type == "comparison":
            render_release_comparison(releases, analyzer)
        elif analysis_type == "timeline":
            render_security_timeline(releases, analyzer)
        
    except Exception as e:
        st.error(f"Failed to load historical data: {e}")


def get_available_releases() -> List[Dict[str, Any]]:
    """Get list of available releases."""
    try:
        with get_db_session() as session:
            releases = session.query(Release).order_by(Release.release_date.desc()).all()
            return [
                {
                    "id": r.id,
                    "version": r.version,
                    "release_date": r.release_date,
                    "support_status": r.support_status
                }
                for r in releases
            ]
    except Exception as e:
        st.error(f"Failed to get releases: {e}")
        return []


def render_historical_controls(releases: List[Dict[str, Any]], current_release_id: int) -> str:
    """Render controls for historical analysis."""
    col1, col2, col3 = st.columns(3)
    
    with col1:
        analysis_type = st.selectbox(
            "Analysis Type:",
            options=["trends", "comparison", "timeline"],
            format_func=lambda x: {
                "trends": "📊 Security Trends",
                "comparison": "⚖️ Release Comparison", 
                "timeline": "📅 Security Timeline"
            }[x],
            key="historical_analysis_type"
        )
    
    with col2:
        time_period = st.selectbox(
            "Time Period:",
            options=[30, 90, 180, 365],
            format_func=lambda x: f"Last {x} days",
            index=2,
            key="historical_time_period"
        )
    
    with col3:
        include_snapshots = st.checkbox(
            "Include Snapshots",
            value=True,
            help="Include historical snapshot data for trend analysis",
            key="include_snapshots"
        )
    
    return analysis_type


def render_security_trends(release_id: int, analyzer: CVEAnalyzer):
    """Render security trends over time for a specific release."""
    st.subheader("📊 Security Trends Over Time")
    
    try:
        # Get time period from controls
        time_period = st.session_state.get("historical_time_period", 90)
        
        # Get security trends
        trends_data = analyzer.get_security_trends(release_id, days=time_period)
        
        if not trends_data["snapshots"]:
            st.info("No historical snapshot data available for trend analysis.")
            st.info("💡 Data snapshots are created during each refresh. Perform a few data refreshes over time to see trends.")
            return
        
        # Create trends visualization
        render_trends_charts(trends_data)
        
        # Show trend analysis
        render_trend_analysis(trends_data)
        
    except Exception as e:
        st.error(f"Failed to generate security trends: {e}")


def render_trends_charts(trends_data: Dict[str, Any]):
    """Render trend charts."""
    snapshots = trends_data["snapshots"]
    
    if not snapshots:
        return
    
    # Prepare data for plotting
    df = pd.DataFrame(snapshots)
    df['date'] = pd.to_datetime(df['date'])
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            'Total CVEs Over Time',
            'CVE Severity Distribution',
            'Critical & High CVEs Trend',
            'CVE Discovery Rate'
        ),
        specs=[[{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    # Total CVEs trend
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['total_cves'],
            mode='lines+markers',
            name='Total CVEs',
            line=dict(color='#1f77b4', width=3)
        ),
        row=1, col=1
    )
    
    # Severity distribution (stacked area)
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['critical_cves'],
            mode='lines',
            stackgroup='one',
            name='Critical',
            fill='tonexty',
            line=dict(color='#dc3545')
        ),
        row=1, col=2
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['high_cves'],
            mode='lines',
            stackgroup='one',
            name='High',
            fill='tonexty',
            line=dict(color='#fd7e14')
        ),
        row=1, col=2
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['medium_cves'],
            mode='lines',
            stackgroup='one',
            name='Medium',
            fill='tonexty',
            line=dict(color='#ffc107')
        ),
        row=1, col=2
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['low_cves'],
            mode='lines',
            stackgroup='one',
            name='Low',
            fill='tonexty',
            line=dict(color='#28a745')
        ),
        row=1, col=2
    )
    
    # Critical & High CVEs trend
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['critical_cves'],
            mode='lines+markers',
            name='Critical CVEs',
            line=dict(color='#dc3545', width=2)
        ),
        row=2, col=1
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['date'],
            y=df['high_cves'],
            mode='lines+markers',
            name='High CVEs',
            line=dict(color='#fd7e14', width=2)
        ),
        row=2, col=1
    )
    
    # CVE discovery rate (difference between consecutive points)
    if len(df) > 1:
        df['cve_change'] = df['total_cves'].diff()
        fig.add_trace(
            go.Bar(
                x=df['date'][1:],  # Skip first point since diff is NaN
                y=df['cve_change'][1:],
                name='CVE Change',
                marker_color=['#28a745' if x <= 0 else '#dc3545' for x in df['cve_change'][1:]]
            ),
            row=2, col=2
        )
    
    # Update layout
    fig.update_layout(
        height=600,
        title_text="Security Trends Analysis",
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_trend_analysis(trends_data: Dict[str, Any]):
    """Render trend analysis summary."""
    trend_analysis = trends_data.get("trend_analysis", {})
    
    if not trend_analysis:
        return
    
    st.subheader("🔍 Trend Analysis Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Trend indicators
    trend_icons = {
        "increasing": "📈",
        "decreasing": "📉", 
        "stable": "➡️",
        "insufficient_data": "❓"
    }
    
    trend_colors = {
        "increasing": "red",
        "decreasing": "green",
        "stable": "blue",
        "insufficient_data": "gray"
    }
    
    with col1:
        total_trend = trend_analysis.get("total_cves", "insufficient_data")
        st.metric(
            "Total CVEs",
            trend_icons[total_trend],
            delta=total_trend.replace("_", " ").title()
        )
    
    with col2:
        critical_trend = trend_analysis.get("critical_cves", "insufficient_data")
        st.metric(
            "Critical CVEs",
            trend_icons[critical_trend],
            delta=critical_trend.replace("_", " ").title(),
            delta_color=trend_colors[critical_trend]
        )
    
    with col3:
        high_trend = trend_analysis.get("high_cves", "insufficient_data")
        st.metric(
            "High CVEs",
            trend_icons[high_trend],
            delta=high_trend.replace("_", " ").title(),
            delta_color=trend_colors[high_trend]
        )
    
    with col4:
        medium_trend = trend_analysis.get("medium_cves", "insufficient_data")
        st.metric(
            "Medium CVEs",
            trend_icons[medium_trend],
            delta=medium_trend.replace("_", " ").title(),
            delta_color=trend_colors[medium_trend]
        )


def render_release_comparison(releases: List[Dict[str, Any]], analyzer: CVEAnalyzer):
    """Render comparison between releases."""
    st.subheader("⚖️ Release Comparison")
    
    # Release selection
    col1, col2 = st.columns(2)
    
    with col1:
        release_options_1 = {f"{r['version']} ({r['support_status']})": r['id'] for r in releases}
        selected_release_1 = st.selectbox(
            "Base Release:",
            options=list(release_options_1.keys()),
            key="comparison_release_1"
        )
        release_id_1 = release_options_1[selected_release_1]
    
    with col2:
        release_options_2 = {f"{r['version']} ({r['support_status']})": r['id'] for r in releases}
        selected_release_2 = st.selectbox(
            "Compare Release:",
            options=list(release_options_2.keys()),
            key="comparison_release_2"
        )
        release_id_2 = release_options_2[selected_release_2]
    
    if release_id_1 == release_id_2:
        st.warning("⚠️ Please select different releases for comparison.")
        return
    
    try:
        # Get comparison data
        comparison = analyzer.compare_releases(release_id_1, release_id_2)
        
        if not comparison:
            st.error("Failed to generate release comparison.")
            return
        
        # Render comparison
        render_comparison_metrics(comparison)
        render_comparison_charts(comparison)
        render_cve_changes(comparison)
        
    except Exception as e:
        st.error(f"Failed to compare releases: {e}")


def render_comparison_metrics(comparison: Dict[str, Any]):
    """Render comparison metrics."""
    st.subheader("📊 Comparison Metrics")
    
    metrics_1 = comparison["release_1"]["metrics"]
    metrics_2 = comparison["release_2"]["metrics"]
    differences = comparison["differences"]
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Images",
            metrics_2.total_images,
            delta=differences["total_images"],
            delta_color="inverse" if differences["total_images"] > 0 else "normal"
        )
    
    with col2:
        st.metric(
            "Total CVEs",
            metrics_2.total_cves,
            delta=differences["total_cves"],
            delta_color="inverse" if differences["total_cves"] > 0 else "normal"
        )
    
    with col3:
        st.metric(
            "Unique CVEs",
            metrics_2.unique_cves,
            delta=differences["unique_cves"],
            delta_color="inverse" if differences["unique_cves"] > 0 else "normal"
        )
    
    with col4:
        st.metric(
            "Critical CVEs",
            metrics_2.critical_cves,
            delta=differences["critical_cves"],
            delta_color="inverse" if differences["critical_cves"] > 0 else "normal"
        )
    
    with col5:
        st.metric(
            "Risk Score",
            f"{metrics_2.risk_score:.1f}",
            delta=f"{differences['risk_score']:+.1f}",
            delta_color="inverse" if differences["risk_score"] > 0 else "normal"
        )


def render_comparison_charts(comparison: Dict[str, Any]):
    """Render comparison charts."""
    metrics_1 = comparison["release_1"]["metrics"]
    metrics_2 = comparison["release_2"]["metrics"]
    release_1_name = comparison["release_1"]["version"]
    release_2_name = comparison["release_2"]["version"]
    
    # Create side-by-side comparison charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity distribution comparison
        fig1 = go.Figure()
        
        severities = ['Critical', 'High', 'Medium', 'Low']
        values_1 = [
            metrics_1.critical_cves,
            metrics_1.high_cves,
            metrics_1.medium_cves,
            metrics_1.low_cves
        ]
        values_2 = [
            metrics_2.critical_cves,
            metrics_2.high_cves,
            metrics_2.medium_cves,
            metrics_2.low_cves
        ]
        
        fig1.add_trace(go.Bar(
            name=release_1_name,
            x=severities,
            y=values_1,
            marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745']
        ))
        
        fig1.add_trace(go.Bar(
            name=release_2_name,
            x=severities,
            y=values_2,
            marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
            opacity=0.7
        ))
        
        fig1.update_layout(
            title="CVE Severity Distribution Comparison",
            barmode='group',
            height=400
        )
        
        st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        # Risk score comparison
        fig2 = go.Figure()
        
        fig2.add_trace(go.Indicator(
            mode="gauge+number+delta",
            value=metrics_2.risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"Risk Score Comparison<br>{release_2_name} vs {release_1_name}"},
            delta={'reference': metrics_1.risk_score, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgreen"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 75], 'color': "orange"},
                    {'range': [75, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "gray", 'width': 4},
                    'thickness': 0.75,
                    'value': metrics_1.risk_score
                }
            }
        ))
        
        fig2.update_layout(height=400)
        st.plotly_chart(fig2, use_container_width=True)


def render_cve_changes(comparison: Dict[str, Any]):
    """Render CVE changes between releases."""
    st.subheader("🔄 CVE Changes")
    
    cve_changes = comparison.get("cve_changes", {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Fixed CVEs",
            len(cve_changes.get("fixed", [])),
            delta="Resolved in newer release",
            delta_color="normal"
        )
        
        if cve_changes.get("fixed"):
            with st.expander("View Fixed CVEs"):
                for cve_id in cve_changes["fixed"][:10]:  # Show first 10
                    st.text(f"✅ {cve_id}")
                if len(cve_changes["fixed"]) > 10:
                    st.text(f"... and {len(cve_changes['fixed']) - 10} more")
    
    with col2:
        st.metric(
            "New CVEs",
            len(cve_changes.get("introduced", [])),
            delta="Introduced in newer release",
            delta_color="inverse"
        )
        
        if cve_changes.get("introduced"):
            with st.expander("View New CVEs"):
                for cve_id in cve_changes["introduced"][:10]:  # Show first 10
                    st.text(f"🆕 {cve_id}")
                if len(cve_changes["introduced"]) > 10:
                    st.text(f"... and {len(cve_changes['introduced']) - 10} more")
    
    with col3:
        st.metric(
            "Persistent CVEs",
            len(cve_changes.get("persistent", [])),
            delta="Present in both releases",
            delta_color="off"
        )
        
        if cve_changes.get("persistent"):
            with st.expander("View Persistent CVEs"):
                for cve_id in cve_changes["persistent"][:10]:  # Show first 10
                    st.text(f"⏳ {cve_id}")
                if len(cve_changes["persistent"]) > 10:
                    st.text(f"... and {len(cve_changes['persistent']) - 10} more")


def render_security_timeline(releases: List[Dict[str, Any]], analyzer: CVEAnalyzer):
    """Render security timeline across all releases."""
    st.subheader("📅 Security Timeline")
    
    try:
        # Get metrics for all releases
        timeline_data = []
        
        for release in releases:
            if release["release_date"]:
                metrics = analyzer.get_release_security_metrics(release["id"])
                timeline_data.append({
                    "release": release["version"],
                    "date": release["release_date"],
                    "total_cves": metrics.total_cves,
                    "critical_cves": metrics.critical_cves,
                    "high_cves": metrics.high_cves,
                    "medium_cves": metrics.medium_cves,
                    "low_cves": metrics.low_cves,
                    "risk_score": metrics.risk_score
                })
        
        if not timeline_data:
            st.info("No release date information available for timeline analysis.")
            return
        
        # Sort by date
        timeline_data.sort(key=lambda x: x["date"])
        
        # Create timeline chart
        df = pd.DataFrame(timeline_data)
        
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('CVE Count Over Releases', 'Risk Score Evolution'),
            shared_xaxes=True
        )
        
        # CVE counts
        fig.add_trace(
            go.Scatter(
                x=df['release'],
                y=df['critical_cves'],
                mode='lines+markers',
                name='Critical',
                line=dict(color='#dc3545', width=3),
                marker=dict(size=8)
            ),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Scatter(
                x=df['release'],
                y=df['high_cves'],
                mode='lines+markers',
                name='High',
                line=dict(color='#fd7e14', width=3),
                marker=dict(size=8)
            ),
            row=1, col=1
        )
        
        # Risk score
        fig.add_trace(
            go.Scatter(
                x=df['release'],
                y=df['risk_score'],
                mode='lines+markers',
                name='Risk Score',
                line=dict(color='#6f42c1', width=3),
                marker=dict(size=10),
                yaxis='y2'
            ),
            row=2, col=1
        )
        
        fig.update_layout(
            height=600,
            title_text="Security Evolution Across Releases",
            showlegend=True
        )
        
        fig.update_xaxes(title_text="Release Version", row=2, col=1)
        fig.update_yaxes(title_text="Number of CVEs", row=1, col=1)
        fig.update_yaxes(title_text="Risk Score", row=2, col=1)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Timeline table
        st.subheader("📊 Release Timeline Summary")
        
        timeline_df = pd.DataFrame(timeline_data)
        timeline_df['Release Date'] = pd.to_datetime(timeline_df['date']).dt.strftime('%Y-%m-%d')
        
        st.dataframe(
            timeline_df[['release', 'Release Date', 'total_cves', 'critical_cves', 'high_cves', 'risk_score']],
            use_container_width=True,
            hide_index=True,
            column_config={
                'release': 'Release Version',
                'total_cves': 'Total CVEs',
                'critical_cves': 'Critical',
                'high_cves': 'High',
                'risk_score': st.column_config.NumberColumn('Risk Score', format="%.1f")
            }
        )
        
    except Exception as e:
        st.error(f"Failed to generate security timeline: {e}")