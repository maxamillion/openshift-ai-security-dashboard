"""SQLAlchemy models for OpenShift AI Security Dashboard."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    DECIMAL,
    BigInteger,
    Column,
    Date,
    ForeignKey,
    Integer,
    String,
    Text,
    DateTime,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Mapped, mapped_column

Base = declarative_base()


class Release(Base):
    """OpenShift AI product releases."""
    
    __tablename__ = "releases"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    release_date: Mapped[Optional[datetime]] = mapped_column(Date, nullable=True)
    support_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    
    # Relationships
    container_images: Mapped[List["ContainerImage"]] = relationship(
        "ContainerImage", back_populates="release", cascade="all, delete-orphan"
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        "Snapshot", back_populates="release", cascade="all, delete-orphan"
    )
    
    def __repr__(self) -> str:
        return f"<Release(id={self.id}, version='{self.version}', status='{self.support_status}')>"


class ContainerImage(Base):
    """Container images in OpenShift AI releases."""
    
    __tablename__ = "container_images"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    release_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("releases.id"), nullable=False
    )
    image_name: Mapped[str] = mapped_column(String(255), nullable=False)
    image_tag: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    image_digest: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    registry_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    architecture: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    
    # Relationships
    release: Mapped["Release"] = relationship("Release", back_populates="container_images")
    image_cves: Mapped[List["ImageCVE"]] = relationship(
        "ImageCVE", back_populates="container_image", cascade="all, delete-orphan"
    )
    
    def __repr__(self) -> str:
        return f"<ContainerImage(id={self.id}, name='{self.image_name}', tag='{self.image_tag}')>"


class CVE(Base):
    """Common Vulnerabilities and Exposures."""
    
    __tablename__ = "cves"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1), nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    published_date: Mapped[Optional[datetime]] = mapped_column(Date, nullable=True)
    modified_date: Mapped[Optional[datetime]] = mapped_column(Date, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    
    # Relationships
    image_cves: Mapped[List["ImageCVE"]] = relationship(
        "ImageCVE", back_populates="cve", cascade="all, delete-orphan"
    )
    cve_errata: Mapped[List["CVEErrata"]] = relationship(
        "CVEErrata", back_populates="cve", cascade="all, delete-orphan"
    )
    
    @property
    def url(self) -> str:
        """Generate Red Hat CVE URL."""
        return f"https://access.redhat.com/security/cve/{self.cve_id}"
    
    def __repr__(self) -> str:
        return f"<CVE(id={self.id}, cve_id='{self.cve_id}', severity='{self.severity}')>"


class ImageCVE(Base):
    """Junction table linking container images to CVEs."""
    
    __tablename__ = "image_cves"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    image_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("container_images.id"), nullable=False
    )
    cve_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cves.id"), nullable=False
    )
    affected_package: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    fix_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    
    # Composite unique constraint
    __table_args__ = (
        UniqueConstraint("image_id", "cve_id", "affected_package", name="uq_image_cve_package"),
    )
    
    # Relationships
    container_image: Mapped["ContainerImage"] = relationship(
        "ContainerImage", back_populates="image_cves"
    )
    cve: Mapped["CVE"] = relationship("CVE", back_populates="image_cves")
    
    def __repr__(self) -> str:
        return f"<ImageCVE(image_id={self.image_id}, cve_id={self.cve_id}, package='{self.affected_package}')>"


class Errata(Base):
    """Red Hat security advisories and errata."""
    
    __tablename__ = "errata"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    advisory_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    synopsis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    issue_date: Mapped[Optional[datetime]] = mapped_column(Date, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    
    # Relationships
    cve_errata: Mapped[List["CVEErrata"]] = relationship(
        "CVEErrata", back_populates="errata", cascade="all, delete-orphan"
    )
    
    @property
    def url(self) -> str:
        """Generate Red Hat errata URL."""
        return f"https://access.redhat.com/errata/{self.advisory_id}"
    
    def __repr__(self) -> str:
        return f"<Errata(id={self.id}, advisory_id='{self.advisory_id}', severity='{self.severity}')>"


class CVEErrata(Base):
    """Junction table linking CVEs to errata/advisories."""
    
    __tablename__ = "cve_errata"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cves.id"), nullable=False
    )
    errata_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("errata.id"), nullable=False
    )
    
    # Composite unique constraint
    __table_args__ = (
        UniqueConstraint("cve_id", "errata_id", name="uq_cve_errata"),
    )
    
    # Relationships
    cve: Mapped["CVE"] = relationship("CVE", back_populates="cve_errata")
    errata: Mapped["Errata"] = relationship("Errata", back_populates="cve_errata")
    
    def __repr__(self) -> str:
        return f"<CVEErrata(cve_id={self.cve_id}, errata_id={self.errata_id})>"


class Snapshot(Base):
    """Historical snapshots of release security state."""
    
    __tablename__ = "snapshots"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    release_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("releases.id"), nullable=False
    )
    snapshot_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    total_images: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_cves: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    critical_cves: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    high_cves: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    medium_cves: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    low_cves: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    snapshot_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    
    # Relationships
    release: Mapped["Release"] = relationship("Release", back_populates="snapshots")
    
    def __repr__(self) -> str:
        return f"<Snapshot(id={self.id}, release_id={self.release_id}, date='{self.snapshot_date}')>"