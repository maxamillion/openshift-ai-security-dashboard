# OpenShift AI Security Dashboard

A comprehensive security overview application for Red Hat OpenShift AI product, providing centralized visibility into container image vulnerabilities, CVE tracking, and security trends across releases.

## Features

- **Security Overview**: Comprehensive dashboard showing security posture across OpenShift AI releases
- **Container Image Analysis**: Detailed security information for all container images
- **CVE Tracking**: Complete vulnerability database with severity analysis and fix status
- **Historical Comparison**: Track security improvements and trends between releases
- **Export Capabilities**: Generate reports in PDF, CSV, and JSON formats
- **Real-time Data Refresh**: Live integration with Red Hat Pyxis and Security Data APIs

## Architecture

### Technology Stack
- **Language**: Python 3.11+
- **Web Framework**: Streamlit
- **Database**: SQLite with SQLAlchemy ORM
- **Package Manager**: uv
- **Testing**: pytest with 80%+ coverage
- **Code Quality**: Black, Flake8, MyPy

### External APIs
- **Red Hat Pyxis API**: Container image metadata and product associations
- **Red Hat Security Data API**: CVE and errata information

## Quick Start

### Prerequisites
- Python 3.11 or higher
- uv package manager (recommended) or pip

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd openshift-ai-security-dashboard
   ```

2. **Install dependencies**:
   ```bash
   make install-dev
   ```

3. **Initialize the database**:
   ```bash
   make db-init
   ```

4. **Run the application**:
   ```bash
   make dev
   ```

5. **Access the dashboard**:
   Open your browser to `http://localhost:8501`

### Development Setup

```bash
# Complete development environment setup
make setup

# Run development server
make dev

# Run tests
make test

# Run code quality checks
make check
```

## Usage

### Data Refresh
1. Click the "🔄 Refresh Data" button in the header
2. Wait for the data refresh process to complete
3. View updated security information across all tabs

### Navigation
- **📊 Dashboard**: Summary metrics and visualizations
- **🐳 Images**: Detailed container image security analysis
- **🔍 CVEs**: Comprehensive vulnerability database
- **📈 Historical**: Trends and release comparisons

### Export Reports
1. Select a release from the dropdown
2. Click the "📤 Export" button
3. Choose format (PDF, CSV, JSON) and scope
4. Download the generated report

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=sqlite:///openshift_ai_security.db

# API Configuration
PYXIS_BASE_URL=https://catalog.redhat.com/api/containers/v1
SECURITY_DATA_BASE_URL=https://access.redhat.com/hydra/rest/securitydata

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
CACHE_TTL=3600
```

### Development Configuration
Create a `.env` file in the project root:
```bash
DEBUG=true
LOG_LEVEL=DEBUG
CACHE_TTL=60
ENABLE_CACHING=true
```

## Development

### Project Structure
```
openshift-ai-security-dashboard/
├── src/
│   ├── app.py              # Main Streamlit application
│   ├── config.py           # Configuration management
│   ├── database/
│   │   ├── models.py       # SQLAlchemy models
│   │   └── connection.py   # Database connection
│   ├── api/
│   │   ├── pyxis.py        # Pyxis API client
│   │   └── security.py     # Security Data API client
│   ├── services/
│   │   ├── data_refresh.py # Data refresh logic
│   │   ├── cve_analyzer.py # CVE analysis
│   │   └── export.py       # Export functionality
│   ├── ui/
│   │   ├── dashboard.py    # Dashboard tab
│   │   ├── images.py       # Images tab
│   │   ├── cves.py         # CVEs tab
│   │   └── historical.py   # Historical tab
│   └── utils/
│       ├── cache.py        # Caching utilities
│       └── formatters.py   # Data formatters
├── tests/                  # Test suite
├── docs/                   # Documentation
├── Makefile               # Development commands
└── pyproject.toml         # Project configuration
```

### Available Commands

```bash
# Development
make dev           # Run development server
make test          # Run test suite
make test-cov      # Run tests with coverage
make lint          # Run linting
make format        # Format code
make type-check    # Run type checking

# Database
make db-init       # Initialize database
make db-migrate    # Run migrations
make db-seed       # Seed test data
make db-reset      # Reset database

# Quality
make check         # Run all quality checks
make clean         # Clean temporary files

# Build
make build         # Build application
make docker-build  # Build Docker image
make docker-run    # Run in Docker
```

### Testing

Run the test suite:
```bash
# All tests
make test

# With coverage
make test-cov

# Specific test file
pytest tests/test_services/test_cve_analyzer.py -v

# Integration tests only
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

### Code Quality

The project uses several tools to maintain code quality:

- **Black**: Code formatting
- **Flake8**: Linting and style checking
- **MyPy**: Static type checking
- **Pre-commit**: Automated quality checks

Set up pre-commit hooks:
```bash
make pre-commit-install
```

## API Integration

### Red Hat Pyxis API
- **Purpose**: Container image metadata and vulnerabilities
- **Authentication**: Public access (no API key required)
- **Rate Limits**: Follows respectful usage patterns

### Red Hat Security Data API
- **Purpose**: CVE details and errata information
- **Authentication**: Public access (no API key required)
- **Rate Limits**: Implements exponential backoff

## Database Schema

The application uses SQLite with the following main tables:

- **releases**: OpenShift AI product releases
- **container_images**: Container images in each release
- **cves**: Common Vulnerabilities and Exposures
- **image_cves**: Relationships between images and CVEs
- **errata**: Red Hat security advisories
- **cve_errata**: Relationships between CVEs and errata
- **snapshots**: Historical security state snapshots

## Deployment

### Docker Deployment

```bash
# Build image
make docker-build

# Run container
make docker-run

# Or with docker-compose
docker-compose up -d
```

### Production Deployment

1. Set production environment variables
2. Use a production WSGI server
3. Configure external database (PostgreSQL recommended)
4. Set up reverse proxy (nginx)
5. Enable SSL/TLS

## Performance

### Response Time Targets
- Page load: < 2 seconds
- Data refresh: < 30 seconds
- Export generation: < 10 seconds
- Filter/sort operations: < 500ms

### Scalability
- Supports up to 500 container images per release
- Handles up to 10,000 CVEs
- Automatic pagination for large datasets
- Intelligent caching reduces API calls

## Security

### Data Security
- No storage of sensitive credentials
- Input sanitization and validation
- Parameterized database queries
- Secure file handling for exports

### Application Security
- Runs with minimal privileges
- Regular dependency updates
- Security headers in responses
- Content Security Policy

## Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Reinitialize database
make db-reset
```

**API Rate Limiting**
```bash
# Check API health
curl https://catalog.redhat.com/api/containers/v1/products?page_size=1
```

**Memory Issues with Large Datasets**
- Reduce pagination size in configuration
- Enable aggressive caching
- Use filtering to limit data scope

### Debug Mode
Enable debug mode for detailed logging:
```bash
DEBUG=true streamlit run src/app.py
```

### Log Analysis
```bash
# View application logs
tail -f logs/application.log

# Check error logs
grep ERROR logs/application.log
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run quality checks: `make check`
5. Submit a pull request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write comprehensive tests
- Document new features
- Update changelog

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation

## Changelog

### v1.0.0 (2025-08-08)
- Initial release
- Complete security dashboard implementation
- Red Hat API integration
- Export functionality
- Historical analysis
- Comprehensive test suite