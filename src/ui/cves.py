"""CVEs tab for OpenShift AI Security Dashboard."""

import streamlit as st
import pandas as pd
from typing import List, Optional, Tuple
from datetime import datetime, timedelta

from ..services.cve_analyzer import CVEAnalyzer, CVEInfo
from ..config import config


def render_cves_tab(release_id: int, analyzer: CVEAnalyzer):
    """Render the CVEs tab."""
    try:
        st.subheader("🔍 Common Vulnerabilities and Exposures (CVEs)")
        
        # Render filters
        filters = render_cve_filters()
        
        # Get filtered CVEs
        cves, total_count = get_filtered_cves(release_id, analyzer, filters)
        
        # Show summary
        render_cve_summary(cves, total_count, filters)
        
        st.markdown("---")
        
        # Render CVEs table
        render_cves_table(cves, total_count, filters)
        
    except Exception as e:
        st.error(f"Failed to load CVE data: {e}")


def render_cve_filters() -> dict:
    """Render CVE filters and return filter values."""
    st.subheader("🔍 Filters")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # Severity filter
        severity_options = ["Critical", "High", "Medium", "Low", "Unknown"]
        selected_severities = st.multiselect(
            "Severity:",
            options=severity_options,
            default=severity_options,
            key="cve_severity_filter"
        )
    
    with col2:
        # Fix status filter
        fix_status_options = ["fixed", "unfixed", "unknown"]
        selected_fix_status = st.multiselect(
            "Fix Status:",
            options=fix_status_options,
            default=fix_status_options,
            key="cve_fix_status_filter"
        )
    
    with col3:
        # Date range filter
        date_range_options = {
            "All Time": None,
            "Last 30 days": 30,
            "Last 90 days": 90,
            "Last Year": 365,
            "Last 2 Years": 730
        }
        
        selected_date_range = st.selectbox(
            "Published Date:",
            options=list(date_range_options.keys()),
            index=0,
            key="cve_date_filter"
        )
        
        date_range_days = date_range_options[selected_date_range]
    
    with col4:
        # CVE ID search
        cve_search = st.text_input(
            "Search CVE ID:",
            placeholder="CVE-2024-1234",
            key="cve_id_search"
        )
    
    # Additional filters in expandable section
    with st.expander("🔧 Advanced Filters"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # CVSS score range
            cvss_range = st.slider(
                "CVSS Score Range:",
                min_value=0.0,
                max_value=10.0,
                value=(0.0, 10.0),
                step=0.1,
                key="cve_cvss_filter"
            )
        
        with col2:
            # Affected images count
            min_affected_images = st.number_input(
                "Min Affected Images:",
                min_value=0,
                value=0,
                key="cve_min_images_filter"
            )
        
        with col3:
            # Sort options
            sort_options = {
                "Severity + CVSS (Desc)": "default",
                "Published Date (Newest)": "published_desc",
                "Published Date (Oldest)": "published_asc",
                "Affected Images (Most)": "affected_desc",
                "CVSS Score (Highest)": "cvss_desc",
                "CVE ID (A-Z)": "cve_id_asc"
            }
            
            sort_by = st.selectbox(
                "Sort by:",
                options=list(sort_options.keys()),
                index=0,
                key="cve_sort"
            )
    
    return {
        "severities": selected_severities,
        "fix_status": selected_fix_status,
        "date_range_days": date_range_days,
        "cve_search": cve_search.strip(),
        "cvss_range": cvss_range,
        "min_affected_images": min_affected_images,
        "sort_by": sort_options[sort_by]
    }


def get_filtered_cves(release_id: int, analyzer: CVEAnalyzer, filters: dict) -> Tuple[List[CVEInfo], int]:
    """Get filtered CVEs based on current filters."""
    # Build filter parameters for the analyzer
    severity_filter = filters["severities"] if filters["severities"] else None
    fix_status_filter = filters["fix_status"] if filters["fix_status"] else None
    
    # Get pagination parameters
    page_size = st.session_state.get("cve_page_size", config.CVE_PAGINATION_SIZE)
    page = st.session_state.get("cve_page", 1)
    offset = (page - 1) * page_size
    
    # Get CVEs from analyzer
    cves, total_count = analyzer.get_cve_details(
        release_id=release_id,
        severity_filter=severity_filter,
        fix_status_filter=fix_status_filter,
        limit=page_size,
        offset=offset
    )
    
    # Apply additional client-side filters
    filtered_cves = []
    
    for cve in cves:
        # CVE ID search filter
        if filters["cve_search"] and filters["cve_search"].lower() not in cve.cve_id.lower():
            continue
        
        # Date range filter
        if filters["date_range_days"] and cve.published_date:
            cutoff_date = datetime.now().date() - timedelta(days=filters["date_range_days"])
            if cve.published_date < cutoff_date:
                continue
        
        # CVSS score filter
        if cve.cvss_score is not None:
            if not (filters["cvss_range"][0] <= cve.cvss_score <= filters["cvss_range"][1]):
                continue
        
        # Minimum affected images filter
        if cve.affected_images_count < filters["min_affected_images"]:
            continue
        
        filtered_cves.append(cve)
    
    return filtered_cves, total_count


def render_cve_summary(cves: List[CVEInfo], total_count: int, filters: dict):
    """Render CVE summary statistics."""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    filtered_count = len(cves)
    
    # Calculate summary stats
    critical_count = sum(1 for cve in cves if cve.severity == "Critical")
    high_count = sum(1 for cve in cves if cve.severity == "High")
    
    # Average CVSS score
    cvss_scores = [cve.cvss_score for cve in cves if cve.cvss_score is not None]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    
    # Recent CVEs (last 30 days)
    recent_date = datetime.now().date() - timedelta(days=30)
    recent_count = sum(1 for cve in cves if cve.published_date and cve.published_date >= recent_date)
    
    with col1:
        st.metric(
            "Showing CVEs",
            f"{filtered_count:,}",
            delta=f"of {total_count:,} total"
        )
    
    with col2:
        st.metric(
            "Critical",
            critical_count,
            delta=f"{critical_count/filtered_count*100:.1f}%" if filtered_count > 0 else "0%"
        )
    
    with col3:
        st.metric(
            "High",
            high_count,
            delta=f"{high_count/filtered_count*100:.1f}%" if filtered_count > 0 else "0%"
        )
    
    with col4:
        st.metric(
            "Avg CVSS Score",
            f"{avg_cvss:.1f}" if avg_cvss > 0 else "N/A",
            delta=f"from {len(cvss_scores)} scored CVEs" if cvss_scores else None
        )
    
    with col5:
        st.metric(
            "Recent (30d)",
            recent_count,
            delta=f"{recent_count/filtered_count*100:.1f}%" if filtered_count > 0 else "0%"
        )


def render_cves_table(cves: List[CVEInfo], total_count: int, filters: dict):
    """Render the main CVEs table with pagination."""
    if not cves:
        st.info("No CVEs match the current filters.")
        return
    
    # Pagination controls
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        page_size = st.selectbox(
            "Items per page:",
            options=[10, 25, 50, 100],
            index=1,
            key="cve_page_size"
        )
    
    with col2:
        # Calculate pagination
        total_pages = (total_count - 1) // page_size + 1
        
        if total_pages > 1:
            page = st.number_input(
                "Page:",
                min_value=1,
                max_value=total_pages,
                value=st.session_state.get("cve_page", 1),
                key="cve_page"
            )
            
            start_idx = (page - 1) * page_size + 1
            end_idx = min(page * page_size, total_count)
            st.caption(f"Showing {start_idx}-{end_idx} of {total_count:,} CVEs")
    
    with col3:
        if st.button("🔄 Refresh", key="refresh_cves"):
            st.rerun()
    
    # Create DataFrame
    df_data = []
    for cve in cves:
        df_data.append({
            'CVE ID': cve.cve_id,
            'Severity': cve.severity or 'Unknown',
            'CVSS Score': f"{cve.cvss_score:.1f}" if cve.cvss_score else 'N/A',
            'Affected Images': cve.affected_images_count,
            'Affected Packages': ', '.join(cve.affected_packages[:2]) + ('...' if len(cve.affected_packages) > 2 else ''),
            'Fix Status': cve.fix_status or 'Unknown',
            'Published': cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'Unknown',
            'Description': (cve.description or 'No description available')[:100] + '...' if cve.description and len(cve.description) > 100 else (cve.description or 'No description available'),
            'URL': f"https://access.redhat.com/security/cve/{cve.cve_id}"
        })
    
    df = pd.DataFrame(df_data)
    
    # Style the dataframe
    def style_severity(val):
        color_map = {
            'Critical': 'background-color: #f8d7da; color: #721c24; font-weight: bold',
            'High': 'background-color: #fff3cd; color: #856404; font-weight: bold',
            'Medium': 'background-color: #d1ecf1; color: #0c5460',
            'Low': 'background-color: #d4edda; color: #155724',
            'Unknown': 'background-color: #f8f9fa; color: #495057'
        }
        return color_map.get(val, '')
    
    def style_cvss_score(val):
        if val == 'N/A':
            return 'color: #6c757d'
        try:
            score = float(val)
            if score >= 9.0:
                return 'background-color: #f8d7da; color: #721c24; font-weight: bold'
            elif score >= 7.0:
                return 'background-color: #fff3cd; color: #856404; font-weight: bold'
            elif score >= 4.0:
                return 'background-color: #d1ecf1; color: #0c5460'
            else:
                return 'background-color: #d4edda; color: #155724'
        except ValueError:
            return ''
    
    def style_fix_status(val):
        color_map = {
            'fixed': 'background-color: #d4edda; color: #155724',
            'unfixed': 'background-color: #f8d7da; color: #721c24',
            'Unknown': 'background-color: #f8f9fa; color: #495057'
        }
        return color_map.get(val, '')
    
    styled_df = df.style.applymap(style_severity, subset=['Severity'])
    styled_df = styled_df.applymap(style_cvss_score, subset=['CVSS Score'])
    styled_df = styled_df.applymap(style_fix_status, subset=['Fix Status'])
    
    # Configure columns
    column_config = {
        'CVE ID': st.column_config.LinkColumn(
            'CVE ID',
            help="Click to view CVE details on Red Hat Security",
            width='medium'
        ),
        'Severity': st.column_config.TextColumn('Severity', width='small'),
        'CVSS Score': st.column_config.TextColumn('CVSS', width='small'),
        'Affected Images': st.column_config.NumberColumn('Images', width='small'),
        'Affected Packages': st.column_config.TextColumn('Packages', width='large'),
        'Fix Status': st.column_config.TextColumn('Fix Status', width='small'),
        'Published': st.column_config.TextColumn('Published', width='medium'),
        'Description': st.column_config.TextColumn('Description', width='large'),
        'URL': None  # Hide URL column since CVE ID is already a link
    }
    
    # Display the table with selection
    selected_rows = st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        column_config=column_config,
        selection_mode="single-row",
        on_select="rerun",
        key="cves_table"
    )
    
    # Show detailed view for selected CVE
    if selected_rows.selection and len(selected_rows.selection.rows) > 0:
        selected_idx = selected_rows.selection.rows[0]
        selected_cve = cves[selected_idx]
        render_cve_details(selected_cve)


def render_cve_details(cve: CVEInfo):
    """Render detailed view for a selected CVE."""
    st.markdown("---")
    st.subheader(f"🔍 CVE Details: {cve.cve_id}")
    
    # Basic CVE information
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Basic Information**")
        
        # CVE ID with link
        st.markdown(f"**CVE ID:** [{cve.cve_id}](https://access.redhat.com/security/cve/{cve.cve_id})")
        
        # Severity with styling
        severity_color = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢',
            'Unknown': '⚪'
        }
        severity_icon = severity_color.get(cve.severity, '⚪')
        st.markdown(f"**Severity:** {severity_icon} {cve.severity or 'Unknown'}")
        
        # CVSS Score
        if cve.cvss_score:
            st.markdown(f"**CVSS Score:** {cve.cvss_score:.1f}/10.0")
        else:
            st.markdown("**CVSS Score:** Not Available")
        
        # Dates
        if cve.published_date:
            st.markdown(f"**Published:** {cve.published_date.strftime('%Y-%m-%d')}")
        
        if cve.modified_date:
            st.markdown(f"**Modified:** {cve.modified_date.strftime('%Y-%m-%d')}")
    
    with col2:
        st.markdown("**Impact Information**")
        st.markdown(f"**Affected Images:** {cve.affected_images_count}")
        st.markdown(f"**Fix Status:** {cve.fix_status or 'Unknown'}")
        
        if cve.affected_packages:
            st.markdown("**Affected Packages:**")
            for package in cve.affected_packages[:5]:  # Show first 5 packages
                st.markdown(f"• `{package}`")
            if len(cve.affected_packages) > 5:
                st.markdown(f"• ... and {len(cve.affected_packages) - 5} more")
        
        # Fix status indicator
        if cve.fix_status == "fixed":
            st.success("✅ Fix Available")
        elif cve.fix_status == "unfixed":
            st.error("❌ No Fix Available")
        else:
            st.warning("⚠️ Fix Status Unknown")
    
    # Description
    if cve.description:
        st.markdown("**Description**")
        st.markdown(cve.description)
    
    # Additional information
    st.markdown("**Additional Resources**")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.link_button(
            "🔗 Red Hat CVE Page",
            f"https://access.redhat.com/security/cve/{cve.cve_id}",
            help="View official Red Hat CVE details"
        )
    
    with col2:
        st.link_button(
            "🌐 MITRE CVE",
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve_id}",
            help="View CVE details on MITRE"
        )
    
    with col3:
        st.link_button(
            "📊 NVD Database",
            f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            help="View CVE details on NIST NVD"
        )
    
    # Timeline information
    if cve.published_date:
        days_since_published = (datetime.now().date() - cve.published_date).days
        
        st.markdown("**Timeline**")
        
        if days_since_published < 30:
            st.info(f"🆕 Recently published ({days_since_published} days ago)")
        elif days_since_published < 90:
            st.warning(f"⏰ Published {days_since_published} days ago")
        else:
            st.text(f"📅 Published {days_since_published} days ago")
    
    # Action buttons
    st.markdown("**Actions**")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📋 Copy CVE ID", key=f"copy_{cve.cve_id}"):
            st.write(f"CVE ID: {cve.cve_id}")
    
    with col2:
        if st.button("📊 Impact Analysis", key=f"analysis_{cve.cve_id}"):
            st.info("Feature coming soon: Detailed impact analysis")
    
    with col3:
        if st.button("📤 Export Report", key=f"export_{cve.cve_id}"):
            st.info("Feature coming soon: Export CVE report")