from sqlalchemy.orm import Query
from sqlalchemy import create_engine
from contextlib import contextmanager
from fastapi import HTTPException, status
from sqlalchemy.orm import sessionmaker, declarative_base

from ..core.config import settings


DATABASE_URL = settings.DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=20,
    max_overflow=20,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def temp_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def authorized_query(query, user_id: int):
    pass
