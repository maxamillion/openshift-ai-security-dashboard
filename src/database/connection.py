"""Database connection and initialization for OpenShift AI Security Dashboard."""

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from .models import Base


# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///openshift_ai_security.db")
TEST_DATABASE_URL = "sqlite:///:memory:"


def get_database_url(test_mode: bool = False) -> str:
    """Get the appropriate database URL."""
    if test_mode or "pytest" in sys.modules:
        return TEST_DATABASE_URL
    return DATABASE_URL


def create_database_engine(test_mode: bool = False) -> Engine:
    """Create a database engine with appropriate configuration."""
    db_url = get_database_url(test_mode)
    
    if db_url.startswith("sqlite"):
        # SQLite-specific configuration
        engine = create_engine(
            db_url,
            poolclass=StaticPool,
            connect_args={
                "check_same_thread": False,
                "timeout": 20,
            },
            echo=os.getenv("DEBUG", "").lower() == "true",
        )
        
        # Enable foreign key constraints for SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.execute("PRAGMA mmap_size=268435456")  # 256MB
            cursor.close()
    else:
        # PostgreSQL or other database configuration
        engine = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=os.getenv("DEBUG", "").lower() == "true",
        )
    
    return engine


# Global engine and session factory
_engine = None
_session_factory = None


def get_engine() -> Engine:
    """Get the global database engine."""
    global _engine
    if _engine is None:
        _engine = create_database_engine()
    return _engine


def get_session_factory() -> sessionmaker:
    """Get the global session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine())
    return _session_factory


def init_database(engine: Engine = None) -> None:
    """Initialize the database schema."""
    if engine is None:
        engine = get_engine()
    
    # Create all tables
    Base.metadata.create_all(engine)
    print("Database schema initialized successfully.")


def reset_database(engine: Engine = None) -> None:
    """Reset the database by dropping and recreating all tables."""
    if engine is None:
        engine = get_engine()
    
    # Drop all tables
    Base.metadata.drop_all(engine)
    print("Database tables dropped.")
    
    # Recreate all tables
    Base.metadata.create_all(engine)
    print("Database schema recreated successfully.")


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Get a database session with automatic cleanup."""
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def health_check() -> bool:
    """Check if the database connection is healthy."""
    try:
        with get_db_session() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False


def get_database_info() -> dict:
    """Get information about the database."""
    engine = get_engine()
    
    info = {
        "url": str(engine.url),
        "driver": engine.dialect.name,
        "pool_size": getattr(engine.pool, "size", None),
        "checked_out_connections": getattr(engine.pool, "checkedout", None),
        "overflow": getattr(engine.pool, "overflow", None),
        "invalid_connections": getattr(engine.pool, "invalidated", None),
    }
    
    # Check if database file exists (for SQLite)
    if engine.url.drivername == "sqlite" and engine.url.database:
        db_path = Path(engine.url.database)
        info.update({
            "database_exists": db_path.exists(),
            "database_size": db_path.stat().st_size if db_path.exists() else 0,
            "database_path": str(db_path.absolute()),
        })
    
    return info


def seed_test_data() -> None:
    """Seed the database with test data for development."""
    from datetime import datetime, date
    from .models import Release, ContainerImage, CVE, ImageCVE, Errata, CVEErrata, Snapshot
    
    with get_db_session() as session:
        # Create sample releases
        release_1 = Release(
            version="2.0.0",
            release_date=date(2024, 6, 1),
            support_status="supported"
        )
        release_2 = Release(
            version="2.1.0",
            release_date=date(2024, 8, 1),
            support_status="supported"
        )
        
        session.add_all([release_1, release_2])
        session.flush()  # Get IDs
        
        # Create sample container images
        image_1 = ContainerImage(
            release_id=release_1.id,
            image_name="openshift-ai/workbench",
            image_tag="2.0.0",
            image_digest="sha256:abc123...",
            registry_path="registry.redhat.io/ubi8/ubi",
            architecture="amd64",
            size_bytes=1000000000
        )
        
        image_2 = ContainerImage(
            release_id=release_1.id,
            image_name="openshift-ai/model-server",
            image_tag="2.0.0",
            image_digest="sha256:def456...",
            registry_path="registry.redhat.io/ubi8/ubi",
            architecture="amd64",
            size_bytes=800000000
        )
        
        session.add_all([image_1, image_2])
        session.flush()
        
        # Create sample CVEs
        cve_1 = CVE(
            cve_id="CVE-2024-12345",
            severity="High",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description="Sample high severity vulnerability",
            published_date=date(2024, 5, 15),
            modified_date=date(2024, 5, 20)
        )
        
        cve_2 = CVE(
            cve_id="CVE-2024-54321",
            severity="Critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Sample critical vulnerability",
            published_date=date(2024, 6, 1),
            modified_date=date(2024, 6, 5)
        )
        
        session.add_all([cve_1, cve_2])
        session.flush()
        
        # Link images to CVEs
        image_cve_1 = ImageCVE(
            image_id=image_1.id,
            cve_id=cve_1.id,
            affected_package="openssl",
            fixed_version="1.1.1k-1",
            fix_status="fixed"
        )
        
        image_cve_2 = ImageCVE(
            image_id=image_1.id,
            cve_id=cve_2.id,
            affected_package="curl",
            fixed_version=None,
            fix_status="unfixed"
        )
        
        session.add_all([image_cve_1, image_cve_2])
        
        # Create sample errata
        errata_1 = Errata(
            advisory_id="RHSA-2024:12345",
            advisory_type="Security Advisory",
            severity="Important",
            synopsis="Security update for openssl",
            description="An update for openssl packages that fixes security vulnerabilities",
            issue_date=date(2024, 5, 20)
        )
        
        session.add(errata_1)
        session.flush()
        
        # Link CVE to errata
        cve_errata_1 = CVEErrata(
            cve_id=cve_1.id,
            errata_id=errata_1.id
        )
        
        session.add(cve_errata_1)
        
        # Create snapshot
        snapshot_1 = Snapshot(
            release_id=release_1.id,
            snapshot_date=datetime.utcnow(),
            total_images=2,
            total_cves=2,
            critical_cves=1,
            high_cves=1,
            medium_cves=0,
            low_cves=0,
            snapshot_data={
                "analysis_date": datetime.utcnow().isoformat(),
                "data_sources": ["pyxis", "security_data_api"],
                "summary": "Initial release analysis"
            }
        )
        
        session.add(snapshot_1)
        
        print("Test data seeded successfully.")


def main():
    """CLI interface for database operations."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("command", choices=["init", "reset", "seed", "info", "health"])
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_database()
    elif args.command == "reset":
        reset_database()
    elif args.command == "seed":
        seed_test_data()
    elif args.command == "info":
        info = get_database_info()
        for key, value in info.items():
            print(f"{key}: {value}")
    elif args.command == "health":
        if health_check():
            print("Database connection is healthy.")
        else:
            print("Database connection failed.")
            sys.exit(1)


if __name__ == "__main__":
    main()