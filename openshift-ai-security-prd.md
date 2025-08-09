# Product Requirements Document
## OpenShift AI Security Overview Prototype

### Document Information
- **Version**: 1.0
- **Date**: August 2025
- **Target Audience**: Claude Code (AI Development Assistant)
- **Project Type**: Security Dashboard Prototype

---

## 1. Executive Summary

### 1.1 Purpose
Create a single-page web application that provides a comprehensive security overview of all container images comprising the Red Hat OpenShift AI product. The application will aggregate container image data from the Red Hat Pyxis API and cross-reference security information from the Red Hat Security Data API.

### 1.2 Core Value Proposition
Provide OpenShift AI users and administrators with a centralized, easy-to-use interface for viewing the security posture of their OpenShift AI deployment, including CVE tracking, errata information, and security trends across releases.

---

## 2. Technical Architecture

### 2.1 Technology Stack
- **Language**: Python 3.11+
- **Web Framework**: Streamlit
- **Package Manager**: uv
- **Database**: SQLite
- **Code Formatter**: Black
- **Testing Framework**: pytest
- **Linter**: flake8
- **Build Tool**: Makefile

### 2.2 External APIs
1. **Red Hat Pyxis API**
   - Base URL: `https://catalog.redhat.com/api/containers/v1/`
   - Purpose: Retrieve container image metadata and product associations
   - Authentication: None required (public access)

2. **Red Hat Security Data API**
   - Base URL: `https://access.redhat.com/hydra/rest/securitydata/`
   - Documentation: https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/
   - Purpose: Retrieve CVE and errata information
   - Authentication: None required (public access)

---

## 3. Functional Requirements

### 3.1 Release Selection
- **Requirement**: Dropdown selector for OpenShift AI releases
- **Data Source**: Query Pyxis API for available OpenShift AI product releases
- **Display**: Show only currently supported releases (filter by support status)
- **Default**: Most recent stable release

### 3.2 Data Refresh Mechanism
- **Manual Refresh Button**: Prominently displayed button to trigger data refresh
- **Cache Strategy**: All data stored in SQLite database
- **User Feedback**: Progress indicator during refresh operations
- **Error Handling**: Graceful fallback to cached data with user notification

### 3.3 Security Dashboard (Main View)

#### 3.3.1 Summary Statistics
- Total number of container images in selected release
- Total unique CVEs across all images
- CVE severity distribution (Critical, High, Medium, Low)
- Comparison metrics with previous release (if available)

#### 3.3.2 Container Images List
- Tabular view of all container images
- Columns:
  - Image name
  - Image tag/version
  - Total CVE count
  - Critical CVE count
  - High CVE count
  - Last updated timestamp
- Sortable columns
- Click-through to detailed image view

#### 3.3.3 Aggregate CVE View
- Paginated list of all unique CVEs
- Default pagination: 25 items per page
- Columns:
  - CVE ID (clickable link)
  - Severity
  - CVSS Score (if available)
  - Affected images count
  - Publication date
  - Fix status
- Filter controls:
  - Severity level (multi-select)
  - Date range
  - Fix status (Fixed/Unfixed)
- CVE links format: `https://access.redhat.com/security/cve/{CVE_ID}`

### 3.4 Detailed Container Image Analysis

#### 3.4.1 Image Security Health View
- Replicate Red Hat Container Catalog security view
- Display:
  - Image metadata (name, tag, digest, size)
  - Security scan date
  - Package count
  - Layer information

#### 3.4.2 CVE Details for Image
- List all CVEs affecting the image
- Group by severity
- Show affected packages
- Include errata information where available

### 3.5 Historical Tracking
- **Requirement**: Track CVE resolution between OpenShift AI versions
- **Implementation**:
  - Store snapshots of each release's security state
  - Provide comparison view between releases
  - Show CVEs that were:
    - Fixed between releases
    - Newly introduced
    - Still present (carried over)

### 3.6 Export Functionality
- **Formats**: PDF, CSV, JSON
- **Scope Options**:
  - Full report (all data for selected release)
  - Filtered view (current filters applied)
  - Single image report
- **PDF Format**: Include charts and summary statistics
- **CSV Format**: Tabular data suitable for spreadsheet analysis
- **JSON Format**: Complete structured data for programmatic use

---

## 4. User Interface Specifications

### 4.1 Layout Structure
```
┌─────────────────────────────────────────────┐
│  Header: OpenShift AI Security Overview     │
│  [Release Dropdown] [Refresh] [Export]      │
├─────────────────────────────────────────────┤
│  Tab 1: Dashboard | Tab 2: Images | Tab 3:  │
│         CVEs | Tab 4: Historical            │
├─────────────────────────────────────────────┤
│                                              │
│  Content Area (Based on selected tab)       │
│                                              │
│  - Dashboard: Summary cards + charts        │
│  - Images: Sortable/filterable table        │
│  - CVEs: Paginated list with filters        │
│  - Historical: Comparison views             │
│                                              │
└─────────────────────────────────────────────┘
```

### 4.2 UI Components
- **Tabs**: Use Streamlit tabs for main navigation
- **Accordions**: For expandable sections within tabs
- **Data Tables**: Use Streamlit dataframes with sorting
- **Charts**: Plotly for interactive visualizations
- **Filters**: Sidebar components for filtering options

---

## 5. Database Schema

### 5.1 Tables

#### releases
```sql
CREATE TABLE releases (
    id INTEGER PRIMARY KEY,
    version VARCHAR(50) UNIQUE NOT NULL,
    release_date DATE,
    support_status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### container_images
```sql
CREATE TABLE container_images (
    id INTEGER PRIMARY KEY,
    release_id INTEGER REFERENCES releases(id),
    image_name VARCHAR(255) NOT NULL,
    image_tag VARCHAR(100),
    image_digest VARCHAR(255) UNIQUE,
    registry_path TEXT,
    architecture VARCHAR(50),
    size_bytes BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### cves
```sql
CREATE TABLE cves (
    id INTEGER PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    cvss_vector TEXT,
    description TEXT,
    published_date DATE,
    modified_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### image_cves
```sql
CREATE TABLE image_cves (
    id INTEGER PRIMARY KEY,
    image_id INTEGER REFERENCES container_images(id),
    cve_id INTEGER REFERENCES cves(id),
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    fix_status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(image_id, cve_id, affected_package)
);
```

#### errata
```sql
CREATE TABLE errata (
    id INTEGER PRIMARY KEY,
    advisory_id VARCHAR(50) UNIQUE NOT NULL,
    advisory_type VARCHAR(20),
    severity VARCHAR(20),
    synopsis TEXT,
    description TEXT,
    issue_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### cve_errata
```sql
CREATE TABLE cve_errata (
    id INTEGER PRIMARY KEY,
    cve_id INTEGER REFERENCES cves(id),
    errata_id INTEGER REFERENCES errata(id),
    UNIQUE(cve_id, errata_id)
);
```

#### snapshots
```sql
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY,
    release_id INTEGER REFERENCES releases(id),
    snapshot_date TIMESTAMP NOT NULL,
    total_images INTEGER,
    total_cves INTEGER,
    critical_cves INTEGER,
    high_cves INTEGER,
    medium_cves INTEGER,
    low_cves INTEGER,
    snapshot_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 6. API Integration Specifications

### 6.1 Pyxis API Integration

#### Get OpenShift AI Product Information
```python
# Endpoint: /products
# Filter for OpenShift AI related products
# Extract product_id for further queries
```

#### Get Container Images for Release
```python
# Endpoint: /images
# Parameters:
#   - filter: product_id, release_version
#   - include: rpm-manifest, vulnerabilities
# Response parsing: Extract image metadata, package lists
```

#### Get Image Security Data
```python
# Endpoint: /images/{image_id}/vulnerabilities
# Response: CVE list with severity and affected packages
```

### 6.2 Security Data API Integration

#### Get CVE Details
```python
# Endpoint: /cve/{cve_id}.json
# Response: Full CVE information including CVSS, descriptions
```

#### Get Errata Information
```python
# Endpoint: /errata/{advisory_id}.json
# Response: Advisory details, affected products, fixes
```

### 6.3 API Call Optimization
- Batch requests where possible
- Implement request caching with TTL
- Use connection pooling
- Implement exponential backoff for retries
- Maximum 3 retry attempts per request

---

## 7. Development Tooling

### 7.1 Makefile Commands
```makefile
# Development commands
make install        # Install dependencies using uv
make dev           # Run development server
make test          # Run pytest suite
make lint          # Run flake8 linter
make format        # Format code with black
make clean         # Clean cache and temp files

# Database commands
make db-init       # Initialize database schema
make db-migrate    # Run database migrations
make db-seed       # Seed with test data

# Build commands
make build         # Build application
make docker-build  # Build Docker image
make docker-run    # Run in Docker container
```

### 7.2 Project Structure
```
openshift-ai-security-overview/
├── Makefile
├── pyproject.toml
├── .gitignore
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── app.py              # Main Streamlit application
│   ├── config.py           # Configuration management
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py       # SQLAlchemy models
│   │   ├── connection.py   # Database connection
│   │   └── migrations/     # Database migrations
│   ├── api/
│   │   ├── __init__.py
│   │   ├── pyxis.py        # Pyxis API client
│   │   └── security.py     # Security Data API client
│   ├── services/
│   │   ├── __init__.py
│   │   ├── data_refresh.py # Data refresh logic
│   │   ├── cve_analyzer.py # CVE analysis
│   │   └── export.py       # Export functionality
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── dashboard.py    # Dashboard tab
│   │   ├── images.py       # Images tab
│   │   ├── cves.py         # CVEs tab
│   │   └── historical.py   # Historical tab
│   └── utils/
│       ├── __init__.py
│       ├── cache.py        # Caching utilities
│       └── formatters.py   # Data formatters
├── tests/
│   ├── __init__.py
│   ├── conftest.py         # pytest configuration
│   ├── test_api/           # API client tests
│   ├── test_services/      # Service layer tests
│   ├── test_ui/            # UI component tests
│   └── fixtures/           # Test data fixtures
└── docs/
    ├── API.md              # API documentation
    └── DEPLOYMENT.md       # Deployment guide
```

---

## 8. Testing Requirements

### 8.1 Unit Tests
- Minimum 80% code coverage
- Test all API client methods
- Test data transformation logic
- Test database operations
- Mock external API calls

### 8.2 Integration Tests
- Test complete data refresh flow
- Test export functionality
- Test database transactions
- Verify API response handling

### 8.3 Test Data
- Create fixtures for API responses
- Seed database with test data
- Include edge cases (empty responses, malformed data)

---

## 9. Error Handling & Logging

### 9.1 Error Handling
- Graceful degradation when APIs unavailable
- User-friendly error messages
- Automatic fallback to cached data
- Retry logic with exponential backoff

### 9.2 Logging
- Structured logging (JSON format)
- Log levels: DEBUG, INFO, WARNING, ERROR
- Include request/response details for API calls
- Performance metrics for slow operations

---

## 10. Performance Requirements

### 10.1 Response Times
- Page load: < 2 seconds
- Data refresh: < 30 seconds for full refresh
- Export generation: < 10 seconds
- Filter/sort operations: < 500ms

### 10.2 Data Limits
- Support up to 500 container images per release
- Handle up to 10,000 CVEs
- Pagination for lists > 100 items
- Database size limit: 1GB

---

## 11. Security Considerations

### 11.1 Data Security
- No storage of sensitive credentials
- Sanitize all user inputs
- Validate API responses
- Use parameterized database queries

### 11.2 Application Security
- Run with minimal privileges
- Regular dependency updates
- Security headers in responses
- Input validation for export filenames

---

## 12. Implementation Notes for Claude Code

### 12.1 Priority Order
1. Set up project structure and tooling
2. Implement database schema and models
3. Create API clients with mocking
4. Build data refresh service
5. Develop Streamlit UI components
6. Add export functionality
7. Implement historical tracking
8. Write comprehensive tests

### 12.2 Key Considerations
- Use async operations where possible for API calls
- Implement progress indicators for long-running operations
- Cache API responses aggressively
- Use Streamlit session state for UI state management
- Implement proper error boundaries in UI

### 12.3 External Dependencies
```toml
[project.dependencies]
streamlit = "^1.37.0"
sqlalchemy = "^2.0.0"
requests = "^2.32.0"
pandas = "^2.2.0"
plotly = "^5.22.0"
pytest = "^8.3.0"
black = "^24.0.0"
flake8 = "^7.1.0"
python-dotenv = "^1.0.0"
```

---

## 13. Acceptance Criteria

### 13.1 Core Functionality
- [ ] Application loads and displays OpenShift AI releases
- [ ] Data refresh completes successfully
- [ ] All CVEs are clickable with correct links
- [ ] Export functions work for all three formats
- [ ] Historical comparison shows accurate data

### 13.2 Performance
- [ ] Meets all response time requirements
- [ ] Handles maximum data limits without crashes
- [ ] Graceful degradation when APIs unavailable

### 13.3 Quality
- [ ] All tests pass with >80% coverage
- [ ] No flake8 violations
- [ ] Code formatted with black
- [ ] Documentation complete

---

## Appendix A: API Research Notes

Based on research, the OpenShift AI product in Pyxis can be identified through:
- Product search for "OpenShift AI" or "Red Hat OpenShift AI"
- Container images with labels indicating OpenShift AI components
- Registry paths containing "rhoai" or "openshift-ai"

The specific product identifier and release versioning scheme should be discovered programmatically through the Pyxis API during implementation.