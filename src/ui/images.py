"""Images tab for OpenShift AI Security Dashboard."""

import streamlit as st
import pandas as pd
from typing import List, Optional

from ..services.cve_analyzer import CVEAnalyzer, ImageSecurityInfo


def render_images_tab(release_id: int, analyzer: CVEAnalyzer):
    """Render the container images tab."""
    try:
        st.subheader("🐳 Container Images Security Analysis")
        
        # Get image security information
        images = analyzer.get_image_security_info(release_id)
        
        if not images:
            st.info("No container images found for this release.")
            return
        
        # Render filters
        filtered_images = render_image_filters(images)
        
        # Show summary stats
        render_image_summary(filtered_images)
        
        st.markdown("---")
        
        # Render images table
        render_images_table(filtered_images, analyzer)
        
    except Exception as e:
        st.error(f"Failed to load container images: {e}")


def render_image_filters(images: List[ImageSecurityInfo]) -> List[ImageSecurityInfo]:
    """Render filters for images and return filtered results."""
    st.subheader("🔍 Filters")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # Risk level filter
        risk_levels = list(set([img.risk_level for img in images]))
        selected_risk_levels = st.multiselect(
            "Risk Level:",
            options=risk_levels,
            default=risk_levels,
            key="image_risk_filter"
        )
    
    with col2:
        # CVE count filter
        max_cves = max([img.total_cves for img in images]) if images else 0
        cve_range = st.slider(
            "CVE Count Range:",
            min_value=0,
            max_value=max_cves,
            value=(0, max_cves),
            key="image_cve_filter"
        )
    
    with col3:
        # Image name search
        name_search = st.text_input(
            "Search Image Name:",
            placeholder="Enter image name...",
            key="image_name_search"
        )
    
    with col4:
        # Sort by
        sort_options = {
            "Total CVEs (Desc)": lambda x: x.total_cves,
            "Total CVEs (Asc)": lambda x: -x.total_cves,
            "Critical CVEs (Desc)": lambda x: x.critical_cves,
            "Image Name (A-Z)": lambda x: -ord(x.image_name[0].lower()) if x.image_name else 0,
            "Risk Level": lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Minimal": 0}.get(x.risk_level, 0)
        }
        
        sort_by = st.selectbox(
            "Sort by:",
            options=list(sort_options.keys()),
            index=0,
            key="image_sort"
        )
    
    # Apply filters
    filtered_images = images.copy()
    
    # Risk level filter
    if selected_risk_levels:
        filtered_images = [img for img in filtered_images if img.risk_level in selected_risk_levels]
    
    # CVE count filter
    filtered_images = [
        img for img in filtered_images 
        if cve_range[0] <= img.total_cves <= cve_range[1]
    ]
    
    # Name search filter
    if name_search:
        filtered_images = [
            img for img in filtered_images 
            if name_search.lower() in img.image_name.lower()
        ]
    
    # Sort
    if sort_by in sort_options:
        filtered_images.sort(key=sort_options[sort_by], reverse=True)
    
    return filtered_images


def render_image_summary(images: List[ImageSecurityInfo]):
    """Render summary statistics for filtered images."""
    if not images:
        st.warning("No images match the current filters.")
        return
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_images = len(images)
    total_cves = sum(img.total_cves for img in images)
    critical_cves = sum(img.critical_cves for img in images)
    high_cves = sum(img.high_cves for img in images)
    
    # Risk level distribution
    risk_distribution = {}
    for img in images:
        risk_distribution[img.risk_level] = risk_distribution.get(img.risk_level, 0) + 1
    
    with col1:
        st.metric("Filtered Images", total_images)
    
    with col2:
        st.metric("Total CVEs", total_cves)
    
    with col3:
        st.metric("Critical CVEs", critical_cves)
    
    with col4:
        st.metric("High CVEs", high_cves)
    
    with col5:
        high_risk_images = sum(1 for img in images if img.risk_level in ["Critical", "High"])
        st.metric("High Risk Images", high_risk_images)


def render_images_table(images: List[ImageSecurityInfo], analyzer: CVEAnalyzer):
    """Render the main images table."""
    if not images:
        return
    
    # Pagination
    page_size = st.selectbox("Items per page:", [10, 25, 50, 100], index=1, key="images_page_size")
    total_pages = (len(images) - 1) // page_size + 1
    
    if total_pages > 1:
        page = st.number_input(
            "Page:", 
            min_value=1, 
            max_value=total_pages, 
            value=1, 
            key="images_page"
        )
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, len(images))
        page_images = images[start_idx:end_idx]
        
        st.caption(f"Showing {start_idx + 1}-{end_idx} of {len(images)} images")
    else:
        page_images = images
    
    # Create DataFrame
    df_data = []
    for img in page_images:
        df_data.append({
            'Image Name': img.image_name,
            'Tag': img.image_tag or 'latest',
            'Total CVEs': img.total_cves,
            'Critical': img.critical_cves,
            'High': img.high_cves,
            'Medium': img.medium_cves,
            'Low': img.low_cves,
            'Risk Level': img.risk_level,
            'Size (MB)': round(img.size_bytes / (1024*1024), 1) if img.size_bytes else None,
            'Last Updated': img.last_updated.strftime('%Y-%m-%d') if img.last_updated else 'Unknown',
            'Image ID': img.image_id  # Hidden column for details
        })
    
    df = pd.DataFrame(df_data)
    
    # Style the dataframe
    def style_risk_level(val):
        color_map = {
            'Critical': 'background-color: #f8d7da; color: #721c24',
            'High': 'background-color: #fff3cd; color: #856404',
            'Medium': 'background-color: #d1ecf1; color: #0c5460',
            'Low': 'background-color: #d4edda; color: #155724',
            'Minimal': 'background-color: #f8f9fa; color: #495057'
        }
        return color_map.get(val, '')
    
    def style_cve_count(val):
        if isinstance(val, int):
            if val >= 50:
                return 'background-color: #f8d7da; font-weight: bold'
            elif val >= 20:
                return 'background-color: #fff3cd; font-weight: bold'
            elif val >= 5:
                return 'background-color: #d1ecf1'
        return ''
    
    styled_df = df.style.applymap(style_risk_level, subset=['Risk Level'])
    styled_df = styled_df.applymap(style_cve_count, subset=['Total CVEs', 'Critical', 'High'])
    
    # Configure columns
    column_config = {
        'Image Name': st.column_config.TextColumn('Image Name', width='large'),
        'Tag': st.column_config.TextColumn('Tag', width='small'),
        'Total CVEs': st.column_config.NumberColumn('Total CVEs', width='small'),
        'Critical': st.column_config.NumberColumn('Critical', width='small'),
        'High': st.column_config.NumberColumn('High', width='small'), 
        'Medium': st.column_config.NumberColumn('Medium', width='small'),
        'Low': st.column_config.NumberColumn('Low', width='small'),
        'Risk Level': st.column_config.TextColumn('Risk Level', width='medium'),
        'Size (MB)': st.column_config.NumberColumn('Size (MB)', width='small', format="%.1f"),
        'Last Updated': st.column_config.TextColumn('Last Updated', width='medium'),
        'Image ID': None  # Hide this column
    }
    
    # Display the table with selection
    selected_rows = st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        column_config=column_config,
        selection_mode="single-row",
        on_select="rerun",
        key="images_table"
    )
    
    # Show detailed view for selected image
    if selected_rows.selection and len(selected_rows.selection.rows) > 0:
        selected_idx = selected_rows.selection.rows[0]
        selected_image = page_images[selected_idx]
        render_image_details(selected_image, analyzer)


def render_image_details(image: ImageSecurityInfo, analyzer: CVEAnalyzer):
    """Render detailed view for a selected image."""
    st.markdown("---")
    st.subheader(f"📋 Image Details: {image.display_name}")
    
    # Basic image information
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Basic Information**")
        st.text(f"Image Name: {image.image_name}")
        st.text(f"Tag: {image.image_tag or 'latest'}")
        st.text(f"Registry Path: {image.registry_path or 'N/A'}")
        st.text(f"Size: {round(image.size_bytes / (1024*1024), 1) if image.size_bytes else 'N/A'} MB")
        st.text(f"Last Updated: {image.last_updated.strftime('%Y-%m-%d %H:%M:%S') if image.last_updated else 'Unknown'}")
    
    with col2:
        st.markdown("**Security Summary**")
        st.text(f"Risk Level: {image.risk_level}")
        st.text(f"Total CVEs: {image.total_cves}")
        st.text(f"Critical: {image.critical_cves}")
        st.text(f"High: {image.high_cves}")
        st.text(f"Medium: {image.medium_cves}")
        st.text(f"Low: {image.low_cves}")
    
    # CVEs affecting this image
    try:
        cves = analyzer.get_cves_for_image(image.image_id)
        
        if cves:
            st.markdown("**Vulnerabilities Affecting This Image**")
            
            # Create CVE DataFrame
            cve_data = []
            for cve in cves[:20]:  # Limit to top 20 for performance
                cve_data.append({
                    'CVE ID': cve.cve_id,
                    'Severity': cve.severity or 'Unknown',
                    'CVSS Score': cve.cvss_score or 'N/A',
                    'Affected Packages': ', '.join(cve.affected_packages[:3]) + ('...' if len(cve.affected_packages) > 3 else ''),
                    'Fix Status': cve.fix_status or 'Unknown',
                    'Published': cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'Unknown'
                })
            
            cve_df = pd.DataFrame(cve_data)
            
            # Style CVE table
            def style_severity(val):
                color_map = {
                    'Critical': 'background-color: #f8d7da; color: #721c24; font-weight: bold',
                    'High': 'background-color: #fff3cd; color: #856404; font-weight: bold',
                    'Medium': 'background-color: #d1ecf1; color: #0c5460',
                    'Low': 'background-color: #d4edda; color: #155724',
                    'Unknown': 'background-color: #f8f9fa; color: #495057'
                }
                return color_map.get(val, '')
            
            styled_cve_df = cve_df.style.applymap(style_severity, subset=['Severity'])
            
            st.dataframe(
                styled_cve_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    'CVE ID': st.column_config.LinkColumn(
                        'CVE ID',
                        help="Click to view CVE details on Red Hat Security",
                        width='medium'
                    ),
                    'Severity': st.column_config.TextColumn('Severity', width='small'),
                    'CVSS Score': st.column_config.TextColumn('CVSS Score', width='small'),
                    'Affected Packages': st.column_config.TextColumn('Affected Packages', width='large'),
                    'Fix Status': st.column_config.TextColumn('Fix Status', width='small'),
                    'Published': st.column_config.TextColumn('Published', width='medium')
                }
            )
            
            if len(cves) > 20:
                st.caption(f"Showing first 20 of {len(cves)} CVEs. Switch to CVEs tab to see all vulnerabilities.")
        else:
            st.success("✅ No known vulnerabilities affecting this image.")
    
    except Exception as e:
        st.error(f"Failed to load CVE details for image: {e}")
    
    # Action buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔗 View in Registry", key=f"registry_{image.image_id}"):
            if image.registry_path:
                st.write(f"Registry URL: {image.registry_path}")
            else:
                st.warning("Registry path not available")
    
    with col2:
        if st.button("📊 CVE Analysis", key=f"analysis_{image.image_id}"):
            st.info("Feature coming soon: Detailed CVE impact analysis")
    
    with col3:
        if st.button("📋 Export Report", key=f"export_{image.image_id}"):
            st.info("Feature coming soon: Export individual image security report")