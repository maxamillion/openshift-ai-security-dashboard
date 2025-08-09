"""Data formatters and utilities for OpenShift AI Security Dashboard."""

import re
from datetime import datetime, date
from typing import Any, Optional, Union, Dict, List


def format_file_size(size_bytes: Optional[int]) -> str:
    """Format file size in bytes to human-readable format."""
    if size_bytes is None or size_bytes == 0:
        return "N/A"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(size_bytes)
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"


def format_date(date_value: Optional[Union[date, datetime, str]]) -> str:
    """Format date for display."""
    if date_value is None:
        return "Unknown"
    
    if isinstance(date_value, str):
        try:
            # Try to parse ISO format
            if 'T' in date_value:
                date_value = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            else:
                date_value = datetime.fromisoformat(date_value).date()
        except ValueError:
            return "Invalid Date"
    
    if isinstance(date_value, datetime):
        return date_value.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(date_value, date):
        return date_value.strftime('%Y-%m-%d')
    
    return str(date_value)


def format_cvss_score(score: Optional[float]) -> str:
    """Format CVSS score for display."""
    if score is None:
        return "N/A"
    
    score_str = f"{score:.1f}"
    
    # Add severity indicator
    if score >= 9.0:
        return f"{score_str} (Critical)"
    elif score >= 7.0:
        return f"{score_str} (High)"
    elif score >= 4.0:
        return f"{score_str} (Medium)"
    else:
        return f"{score_str} (Low)"


def format_severity(severity: Optional[str]) -> str:
    """Format severity level for display."""
    if not severity:
        return "Unknown"
    
    severity_map = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'moderate': 'Medium',
        'low': 'Low',
        'none': 'None',
        'unknown': 'Unknown'
    }
    
    return severity_map.get(severity.lower(), severity.title())


def format_cve_id(cve_id: str) -> str:
    """Format CVE ID with link."""
    if not cve_id or not cve_id.startswith('CVE-'):
        return cve_id
    
    return f"[{cve_id}](https://access.redhat.com/security/cve/{cve_id})"


def format_image_name(image_name: str, image_tag: Optional[str] = None, max_length: int = 50) -> str:
    """Format container image name for display."""
    if not image_name:
        return "Unknown"
    
    display_name = image_name
    if image_tag and image_tag != "latest":
        display_name = f"{image_name}:{image_tag}"
    
    if len(display_name) > max_length:
        return display_name[:max_length-3] + "..."
    
    return display_name


def format_package_list(packages: List[str], max_items: int = 3) -> str:
    """Format list of packages for display."""
    if not packages:
        return "None"
    
    if len(packages) <= max_items:
        return ", ".join(packages)
    else:
        shown = ", ".join(packages[:max_items])
        remaining = len(packages) - max_items
        return f"{shown}, +{remaining} more"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_percentage(value: float, total: float) -> str:
    """Format percentage for display."""
    if total == 0:
        return "0%"
    
    percentage = (value / total) * 100
    return f"{percentage:.1f}%"


def format_risk_score(score: float) -> str:
    """Format risk score with color indication."""
    if score >= 75:
        return f"{score:.1f} (High Risk)"
    elif score >= 50:
        return f"{score:.1f} (Medium Risk)"
    elif score >= 25:
        return f"{score:.1f} (Low Risk)"
    else:
        return f"{score:.1f} (Minimal Risk)"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem operations."""
    # Remove or replace problematic characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        sanitized = name[:max_name_length] + ('.' + ext if ext else '')
    
    return sanitized or "untitled"


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to maximum length."""
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def format_registry_url(registry_path: Optional[str]) -> str:
    """Format registry URL for display."""
    if not registry_path:
        return "N/A"
    
    # Clean up the URL
    if registry_path.startswith('http://') or registry_path.startswith('https://'):
        return registry_path
    else:
        return f"https://{registry_path}"


def format_advisory_id(advisory_id: str) -> str:
    """Format Red Hat advisory ID with link."""
    if not advisory_id:
        return "N/A"
    
    return f"[{advisory_id}](https://access.redhat.com/errata/{advisory_id})"


def format_release_version(version: str, support_status: Optional[str] = None) -> str:
    """Format release version with support status."""
    if not version:
        return "Unknown"
    
    if support_status:
        status_map = {
            'supported': '✅',
            'maintenance': '⚠️',
            'eol': '❌',
            'deprecated': '⚠️'
        }
        icon = status_map.get(support_status.lower(), '')
        return f"{version} {icon}"
    
    return version


def format_age_in_days(date_value: Optional[Union[date, datetime]]) -> str:
    """Format age in days from a date."""
    if not date_value:
        return "Unknown"
    
    if isinstance(date_value, datetime):
        date_value = date_value.date()
    
    today = date.today()
    age_days = (today - date_value).days
    
    if age_days == 0:
        return "Today"
    elif age_days == 1:
        return "1 day ago"
    elif age_days < 30:
        return f"{age_days} days ago"
    elif age_days < 365:
        months = age_days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    else:
        years = age_days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"


def format_number_with_commas(number: Union[int, float]) -> str:
    """Format number with thousands separators."""
    if isinstance(number, float):
        if number.is_integer():
            return f"{int(number):,}"
        else:
            return f"{number:,.1f}"
    else:
        return f"{number:,}"


def format_export_filename(base_name: str, release_version: str, export_format: str, scope: str) -> str:
    """Generate formatted export filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Sanitize components
    base_name = sanitize_filename(base_name)
    release_version = sanitize_filename(release_version)
    scope = sanitize_filename(scope)
    
    filename = f"{base_name}_{release_version}_{scope}_{timestamp}.{export_format.lower()}"
    return sanitize_filename(filename)


def format_data_table_value(value: Any, column_type: str = "auto") -> str:
    """Format value for data table display."""
    if value is None:
        return "N/A"
    
    if column_type == "auto":
        # Auto-detect type
        if isinstance(value, (int, float)):
            column_type = "number"
        elif isinstance(value, (date, datetime)):
            column_type = "date"
        elif isinstance(value, str) and value.startswith(('http://', 'https://')):
            column_type = "url"
        elif isinstance(value, str) and value.startswith('CVE-'):
            column_type = "cve"
        else:
            column_type = "text"
    
    if column_type == "number":
        return format_number_with_commas(value)
    elif column_type == "date":
        return format_date(value)
    elif column_type == "url":
        return f"[Link]({value})"
    elif column_type == "cve":
        return format_cve_id(value)
    elif column_type == "size":
        return format_file_size(value)
    elif column_type == "percentage":
        return f"{value:.1f}%"
    else:
        return str(value)


def highlight_search_term(text: str, search_term: str) -> str:
    """Highlight search term in text."""
    if not search_term or not text:
        return text
    
    # Case-insensitive highlighting
    pattern = re.compile(re.escape(search_term), re.IGNORECASE)
    return pattern.sub(f"**{search_term}**", text)