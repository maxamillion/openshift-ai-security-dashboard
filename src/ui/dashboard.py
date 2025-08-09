"""Dashboard tab for OpenShift AI Security Dashboard."""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, Any

from ..services.cve_analyzer import CVEAnalyzer


def render_dashboard_tab(release_id: int, analyzer: CVEAnalyzer):
    """Render the main dashboard tab."""
    try:
        # Get security metrics
        metrics = analyzer.get_release_security_metrics(release_id)
        
        # Header metrics cards
        render_summary_metrics(metrics)
        
        st.markdown("---")
        
        # Charts section
        col1, col2 = st.columns(2)
        
        with col1:
            render_severity_distribution_chart(metrics)
            render_fix_status_chart(metrics)
        
        with col2:
            render_risk_gauge(metrics)
            render_cve_statistics_chart(release_id, analyzer)
        
        st.markdown("---")
        
        # Top vulnerable images section
        render_top_vulnerable_images(release_id, analyzer)
        
    except Exception as e:
        st.error(f"Failed to load dashboard data: {e}")


def render_summary_metrics(metrics):
    """Render summary metrics cards."""
    st.subheader("📊 Security Overview")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Images",
            value=metrics.total_images,
            help="Total number of container images in this release"
        )
    
    with col2:
        st.metric(
            label="Total CVEs",
            value=metrics.total_cves,
            help="Total CVE instances across all images"
        )
    
    with col3:
        st.metric(
            label="Unique CVEs",
            value=metrics.unique_cves,
            help="Number of distinct CVEs affecting the release"
        )
    
    with col4:
        critical_delta = f"{metrics.critical_cves}/{metrics.unique_cves}" if metrics.unique_cves > 0 else "0/0"
        st.metric(
            label="Critical CVEs",
            value=metrics.critical_cves,
            delta=critical_delta,
            delta_color="inverse",
            help="Critical severity vulnerabilities"
        )
    
    with col5:
        st.metric(
            label="Risk Score",
            value=f"{metrics.risk_score:.1f}/100",
            delta=f"{metrics.risk_score:.1f}%" if metrics.risk_score > 0 else None,
            delta_color="inverse" if metrics.risk_score > 50 else "normal",
            help="Overall risk score based on severity distribution"
        )


def render_severity_distribution_chart(metrics):
    """Render CVE severity distribution chart."""
    st.subheader("🔍 CVE Severity Distribution")
    
    severity_data = metrics.severity_distribution
    
    # Remove zero values for cleaner chart
    filtered_data = {k: v for k, v in severity_data.items() if v > 0}
    
    if not filtered_data:
        st.info("No CVEs found for this release.")
        return
    
    # Create pie chart
    fig = px.pie(
        values=list(filtered_data.values()),
        names=list(filtered_data.keys()),
        title="CVE Severity Distribution",
        color_discrete_map={
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Unknown': '#6c757d'
        }
    )
    
    fig.update_layout(
        showlegend=True,
        height=400,
        font=dict(size=12)
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_fix_status_chart(metrics):
    """Render fix status distribution chart."""
    st.subheader("🔧 Fix Status Distribution")
    
    fix_data = metrics.fix_status_distribution
    
    # Remove zero values
    filtered_data = {k: v for k, v in fix_data.items() if v > 0}
    
    if not filtered_data:
        st.info("No fix status data available.")
        return
    
    # Create horizontal bar chart
    fig = px.bar(
        x=list(filtered_data.values()),
        y=list(filtered_data.keys()),
        orientation='h',
        title="CVE Fix Status",
        color=list(filtered_data.keys()),
        color_discrete_map={
            'Fixed': '#28a745',
            'Unfixed': '#dc3545',
            'Unknown': '#6c757d'
        }
    )
    
    fig.update_layout(
        showlegend=False,
        height=300,
        xaxis_title="Number of CVEs",
        yaxis_title="Fix Status"
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_risk_gauge(metrics):
    """Render risk score gauge."""
    st.subheader("⚡ Risk Assessment")
    
    # Create gauge chart
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = metrics.risk_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Overall Risk Score"},
        delta = {'reference': 50, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(height=350)
    st.plotly_chart(fig, use_container_width=True)
    
    # Risk level interpretation
    if metrics.risk_score >= 75:
        st.error("🚨 **High Risk** - Immediate attention required")
    elif metrics.risk_score >= 50:
        st.warning("⚠️ **Medium Risk** - Monitor and plan remediation")
    elif metrics.risk_score >= 25:
        st.info("ℹ️ **Low Risk** - Maintain current security posture")
    else:
        st.success("✅ **Minimal Risk** - Good security posture")


def render_cve_statistics_chart(release_id: int, analyzer: CVEAnalyzer):
    """Render CVE statistics and trends."""
    st.subheader("📈 CVE Statistics")
    
    try:
        # Get CVE statistics
        stats = analyzer.get_cve_statistics(release_id)
        
        # Create subplot for age and CVSS distributions
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('CVE Age Distribution', 'CVSS Score Distribution'),
            specs=[[{"type": "bar"}], [{"type": "bar"}]]
        )
        
        # Age distribution
        age_data = stats['age_distribution']
        age_labels = ['<30 days', '30-90 days', '3-12 months', '>1 year', 'Unknown']
        age_values = [
            age_data['less_than_30_days'],
            age_data['30_to_90_days'], 
            age_data['90_days_to_1_year'],
            age_data['more_than_1_year'],
            age_data['unknown_age']
        ]
        
        fig.add_trace(
            go.Bar(x=age_labels, y=age_values, name="CVE Age", 
                  marker_color=['#28a745', '#ffc107', '#fd7e14', '#dc3545', '#6c757d']),
            row=1, col=1
        )
        
        # CVSS distribution
        cvss_data = stats['cvss_distribution']
        cvss_labels = ['0.0-3.9', '4.0-6.9', '7.0-8.9', '9.0-10.0', 'No Score']
        cvss_values = [
            cvss_data['0.0_to_3.9'],
            cvss_data['4.0_to_6.9'],
            cvss_data['7.0_to_8.9'], 
            cvss_data['9.0_to_10.0'],
            cvss_data['no_score']
        ]
        
        fig.add_trace(
            go.Bar(x=cvss_labels, y=cvss_values, name="CVSS Score",
                  marker_color=['#28a745', '#ffc107', '#fd7e14', '#dc3545', '#6c757d']),
            row=2, col=1
        )
        
        fig.update_layout(
            height=500,
            showlegend=False,
            title_text="CVE Analysis"
        )
        
        fig.update_xaxes(title_text="Age Range", row=1, col=1)
        fig.update_xaxes(title_text="CVSS Score Range", row=2, col=1)
        fig.update_yaxes(title_text="Number of CVEs", row=1, col=1)
        fig.update_yaxes(title_text="Number of CVEs", row=2, col=1)
        
        st.plotly_chart(fig, use_container_width=True)
        
    except Exception as e:
        st.error(f"Failed to load CVE statistics: {e}")


def render_top_vulnerable_images(release_id: int, analyzer: CVEAnalyzer):
    """Render top vulnerable container images."""
    st.subheader("🐳 Most Vulnerable Container Images")
    
    try:
        # Get top vulnerable images
        top_images = analyzer.get_top_vulnerable_images(release_id, limit=10)
        
        if not top_images:
            st.info("No vulnerable images found.")
            return
        
        # Create DataFrame for display
        df_data = []
        for img in top_images:
            df_data.append({
                'Image Name': img.image_name,
                'Tag': img.image_tag or 'latest',
                'Total CVEs': img.total_cves,
                'Critical': img.critical_cves,
                'High': img.high_cves,
                'Medium': img.medium_cves,
                'Low': img.low_cves,
                'Risk Level': img.risk_level,
                'Size (MB)': round(img.size_bytes / (1024*1024), 1) if img.size_bytes else 'N/A'
            })
        
        df = pd.DataFrame(df_data)
        
        # Style the dataframe
        def style_risk_level(val):
            if val == 'Critical':
                return 'background-color: #f8d7da; color: #721c24'
            elif val == 'High':
                return 'background-color: #fff3cd; color: #856404'
            elif val == 'Medium':
                return 'background-color: #d1ecf1; color: #0c5460'
            elif val == 'Low':
                return 'background-color: #d4edda; color: #155724'
            else:
                return 'background-color: #f8f9fa; color: #495057'
        
        styled_df = df.style.applymap(style_risk_level, subset=['Risk Level'])
        
        st.dataframe(
            styled_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                'Image Name': st.column_config.TextColumn('Image Name', width='large'),
                'Tag': st.column_config.TextColumn('Tag', width='small'),
                'Total CVEs': st.column_config.NumberColumn('Total CVEs', width='small'),
                'Critical': st.column_config.NumberColumn('Critical', width='small'),
                'High': st.column_config.NumberColumn('High', width='small'),
                'Medium': st.column_config.NumberColumn('Medium', width='small'),
                'Low': st.column_config.NumberColumn('Low', width='small'),
                'Risk Level': st.column_config.TextColumn('Risk Level', width='medium'),
                'Size (MB)': st.column_config.NumberColumn('Size (MB)', width='small')
            }
        )
        
        # Create horizontal bar chart for top 5 images
        if len(top_images) >= 5:
            st.subheader("🔝 Top 5 Most Vulnerable Images")
            
            top_5 = top_images[:5]
            image_names = [f"{img.image_name}:{img.image_tag or 'latest'}"[:30] for img in top_5]
            
            fig = go.Figure()
            
            # Add bars for each severity
            fig.add_trace(go.Bar(
                name='Critical',
                y=image_names,
                x=[img.critical_cves for img in top_5],
                orientation='h',
                marker_color='#dc3545'
            ))
            
            fig.add_trace(go.Bar(
                name='High', 
                y=image_names,
                x=[img.high_cves for img in top_5],
                orientation='h',
                marker_color='#fd7e14'
            ))
            
            fig.add_trace(go.Bar(
                name='Medium',
                y=image_names, 
                x=[img.medium_cves for img in top_5],
                orientation='h',
                marker_color='#ffc107'
            ))
            
            fig.add_trace(go.Bar(
                name='Low',
                y=image_names,
                x=[img.low_cves for img in top_5], 
                orientation='h',
                marker_color='#28a745'
            ))
            
            fig.update_layout(
                barmode='stack',
                height=400,
                xaxis_title='Number of CVEs',
                yaxis_title='Container Images',
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
    except Exception as e:
        st.error(f"Failed to load vulnerable images: {e}")