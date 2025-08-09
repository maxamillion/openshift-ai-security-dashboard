"""Main Streamlit application for OpenShift AI Security Dashboard."""

import streamlit as st
import logging
from datetime import datetime
from typing import Optional

from src.config import config
from src.database.connection import get_db_session, health_check, init_database
from src.database.models import Release
from src.services.data_refresh import DataRefreshService, refresh_data_sync
from src.services.cve_analyzer import CVEAnalyzer
from src.services.export import ExportService
from src.ui.dashboard import render_dashboard_tab
from src.ui.images import render_images_tab
from src.ui.cves import render_cves_tab
from src.ui.historical import render_historical_tab

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)


def configure_page():
    """Configure Streamlit page settings."""
    st.set_page_config(**config.get_streamlit_config())
    
    # Custom CSS for better styling
    st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            color: #2E86AB;
            text-align: center;
            margin-bottom: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        .severity-critical {
            color: #dc3545;
            font-weight: bold;
        }
        .severity-high {
            color: #fd7e14;
            font-weight: bold;
        }
        .severity-medium {
            color: #ffc107;
            font-weight: bold;
        }
        .severity-low {
            color: #28a745;
            font-weight: bold;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding-left: 20px;
            padding-right: 20px;
        }
        </style>
    """, unsafe_allow_html=True)


def initialize_session_state():
    """Initialize Streamlit session state variables."""
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True
        st.session_state.selected_release_id = None
        st.session_state.last_refresh = None
        st.session_state.refresh_in_progress = False
        st.session_state.analyzer = CVEAnalyzer()
        st.session_state.export_service = ExportService()


def check_database_health():
    """Check database connectivity and initialize if needed."""
    if not health_check():
        st.error("⚠️ Database connection failed. Attempting to initialize...")
        try:
            init_database()
            st.success("✅ Database initialized successfully.")
        except Exception as e:
            st.error(f"❌ Failed to initialize database: {e}")
            st.stop()


def get_available_releases() -> list:
    """Get list of available releases."""
    try:
        with get_db_session() as session:
            releases = session.query(Release).order_by(Release.release_date.desc()).all()
            # Convert to dict to avoid session binding issues
            release_data = []
            for release in releases:
                release_data.append({
                    'id': release.id,
                    'version': release.version,
                    'support_status': release.support_status,
                    'release_date': release.release_date
                })
            return release_data
    except Exception as e:
        logger.error(f"Failed to get releases: {e}")
        st.error(f"Failed to load releases: {e}")
        return []


def render_header():
    """Render the application header."""
    st.markdown('<div class="main-header">🛡️ OpenShift AI Security Overview</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        # Release selection
        releases = get_available_releases()
        if releases:
            release_options = {f"{r['version']} ({r['support_status']})": r['id'] for r in releases}
            selected_release = st.selectbox(
                "Select OpenShift AI Release:",
                options=list(release_options.keys()),
                key="release_selector"
            )
            
            if selected_release:
                st.session_state.selected_release_id = release_options[selected_release]
        else:
            st.warning("⚠️ No releases found. Please refresh data to load releases.")
            st.session_state.selected_release_id = None
    
    with col2:
        # Data refresh button
        if st.button("🔄 Refresh Data", disabled=st.session_state.refresh_in_progress):
            refresh_data()
    
    with col3:
        # Export functionality
        if st.session_state.selected_release_id:
            render_export_controls()


def refresh_data():
    """Handle data refresh with progress indication."""
    st.session_state.refresh_in_progress = True
    
    # Create progress containers
    progress_container = st.container()
    
    with progress_container:
        st.info("🔄 Starting data refresh...")
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(progress_info):
            """Update progress display."""
            progress_bar.progress(progress_info.progress_percentage / 100)
            status_text.text(f"Progress: {progress_info.progress_percentage:.1f}% - {progress_info.current_operation}")
            
            # Show errors and warnings
            if progress_info.errors:
                for error in progress_info.errors[-3:]:  # Show last 3 errors
                    st.error(f"❌ {error}")
            
            if progress_info.warnings:
                for warning in progress_info.warnings[-3:]:  # Show last 3 warnings
                    st.warning(f"⚠️ {warning}")
        
        try:
            # Run data refresh
            result = refresh_data_sync(progress_callback=update_progress)
            
            if result.errors:
                st.error(f"❌ Data refresh completed with {len(result.errors)} errors.")
                with st.expander("View Errors"):
                    for error in result.errors:
                        st.text(error)
            else:
                st.success(f"✅ Data refresh completed successfully in {result.elapsed_time:.1f} seconds!")
            
            if result.warnings:
                st.warning(f"⚠️ {len(result.warnings)} warnings occurred during refresh.")
                with st.expander("View Warnings"):
                    for warning in result.warnings:
                        st.text(warning)
            
            st.session_state.last_refresh = datetime.now()
            
        except Exception as e:
            st.error(f"❌ Data refresh failed: {e}")
            logger.exception("Data refresh failed")
        
        finally:
            st.session_state.refresh_in_progress = False
            progress_container.empty()
            st.rerun()


def render_export_controls():
    """Render export controls."""
    with st.popover("📤 Export"):
        export_format = st.selectbox(
            "Format:",
            options=["PDF", "CSV", "JSON"],
            key="export_format"
        )
        
        export_scope = st.selectbox(
            "Scope:",
            options=["Full Report", "Summary", "Filtered View"],
            key="export_scope"
        )
        
        if st.button("Generate Export", key="export_button"):
            try:
                # Map UI values to service values
                format_map = {"PDF": "pdf", "CSV": "csv", "JSON": "json"}
                scope_map = {"Full Report": "full", "Summary": "summary", "Filtered View": "filtered"}
                
                format_val = format_map[export_format]
                scope_val = scope_map[export_scope]
                
                # Check size estimate
                size_estimate = st.session_state.export_service.get_export_size_estimate(
                    st.session_state.selected_release_id, format_val
                )
                
                if not size_estimate["within_limits"]:
                    st.error(f"❌ Export would be too large ({size_estimate['estimated_size_mb']:.1f} MB). "
                            f"Maximum allowed: {size_estimate['max_allowed_mb']} MB")
                    return
                
                with st.spinner(f"Generating {export_format} export..."):
                    filepath = st.session_state.export_service.export_release_data(
                        st.session_state.selected_release_id, format_val, scope_val
                    )
                
                st.success(f"✅ Export generated: {filepath}")
                
                # Provide download link
                with open(filepath, "rb") as file:
                    st.download_button(
                        label=f"Download {export_format}",
                        data=file.read(),
                        file_name=filepath.split('/')[-1],
                        mime=f"application/{format_val}"
                    )
                
            except Exception as e:
                st.error(f"❌ Export failed: {e}")
                logger.exception("Export failed")


def render_main_content():
    """Render the main application content."""
    if not st.session_state.selected_release_id:
        st.info("👆 Please select a release above to view security information.")
        
        # Show basic stats if no release selected
        with get_db_session() as session:
            total_releases = session.query(Release).count()
            if total_releases > 0:
                st.metric("Total Releases Available", total_releases)
        
        return
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🐳 Images", "🔍 CVEs", "📈 Historical"])
    
    with tab1:
        render_dashboard_tab(st.session_state.selected_release_id, st.session_state.analyzer)
    
    with tab2:
        render_images_tab(st.session_state.selected_release_id, st.session_state.analyzer)
    
    with tab3:
        render_cves_tab(st.session_state.selected_release_id, st.session_state.analyzer)
    
    with tab4:
        render_historical_tab(st.session_state.selected_release_id, st.session_state.analyzer)


def render_sidebar():
    """Render the sidebar with additional information and controls."""
    with st.sidebar:
        st.header("ℹ️ Information")
        
        # Show last refresh time
        if st.session_state.last_refresh:
            st.text(f"Last Refresh: {st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Database status
        if health_check():
            st.success("✅ Database Connected")
        else:
            st.error("❌ Database Disconnected")
        
        # Quick stats
        if st.session_state.selected_release_id:
            try:
                metrics = st.session_state.analyzer.get_release_security_metrics(
                    st.session_state.selected_release_id
                )
                
                st.header("📈 Quick Stats")
                st.metric("Total Images", metrics.total_images)
                st.metric("Total CVEs", metrics.total_cves)
                st.metric("Critical CVEs", metrics.critical_cves, 
                         delta=f"-{metrics.fixed_cves} fixed" if metrics.fixed_cves else None)
                st.metric("Risk Score", f"{metrics.risk_score:.1f}/100")
                
            except Exception as e:
                st.error(f"Failed to load quick stats: {e}")
        
        # Configuration info
        st.header("⚙️ Configuration")
        st.text(f"Version: {config.VERSION}")
        st.text(f"Environment: {config.DEBUG and 'Development' or 'Production'}")
        
        # Available exports
        exports = st.session_state.export_service.list_exports()
        if exports:
            st.header("📁 Recent Exports")
            for export in exports[:3]:  # Show last 3 exports
                st.text(f"• {export['filename'][:20]}...")
                st.caption(f"  {export['size_mb']} MB - {export['created_at'].strftime('%m/%d %H:%M')}")


def main():
    """Main application function."""
    try:
        # Initialize application
        configure_page()
        initialize_session_state()
        check_database_health()
        
        # Render UI
        render_header()
        render_sidebar()
        render_main_content()
        
        # Footer
        st.markdown("---")
        st.markdown(
            f"<div style='text-align: center; color: #666; margin-top: 2rem;'>"
            f"OpenShift AI Security Dashboard v{config.VERSION} | "
            f"Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            f"</div>", 
            unsafe_allow_html=True
        )
        
    except Exception as e:
        st.error(f"❌ Application error: {e}")
        logger.exception("Application error")


if __name__ == "__main__":
    main()