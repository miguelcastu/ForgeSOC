from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from forgesoc.persistence.config import DatabaseConfig

type SessionFactory = sessionmaker[Session]


def create_database_engine(config: DatabaseConfig) -> Engine:
    return create_engine(
        config.url,
        echo=config.echo,
        pool_pre_ping=True,
    )


def create_session_factory(engine: Engine) -> SessionFactory:
    return sessionmaker(
        bind=engine,
        class_=Session,
        expire_on_commit=False,
    )
