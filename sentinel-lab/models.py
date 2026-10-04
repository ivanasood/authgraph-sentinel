"""World Monitor Lab - data models.

Ownership (owner_id) and role are the two anchors AuthGraph Sentinel reasons about:
  - owner_id  -> "who owns" a resource
  - role      -> "what access should be permitted"
"""
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, nullable=False, default="viewer")  # admin | analyst | viewer
    password_hash = Column(String, nullable=False)           # sensitive
    api_key = Column(String, nullable=False)                 # sensitive
    created_at = Column(DateTime, default=datetime.utcnow)

    reports = relationship("Report", back_populates="owner")


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)  # sequential -> guessable
    title = Column(String, nullable=False)
    content = Column(Text, default="")
    classification = Column(String, default="internal")  # public | internal | confidential
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="reports")


class Dashboard(Base):
    __tablename__ = "dashboards"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    config = Column(Text, default="{}")
