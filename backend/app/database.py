from sqlmodel import Session, create_engine
from typing import Generator
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load environment variables from .env file
load_dotenv()

# Database URL configuration
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in the environment variables (.env file)")
# Create SQLModel engine
engine = create_engine(
    DATABASE_URL,
    echo=True,  # Set to False in production
    pool_pre_ping=True  # Enable connection pool "pre-ping" feature
)

def get_session() -> Generator[Session, None, None]:
    """
    Get a database session.
    Yields a SQLModel session and ensures it's closed after use.
    """
    with Session(engine) as session:
        try:
            yield session
        finally:
            session.close()

# Function to initialize database (create all tables)
def init_db() -> None:
    """
    Initialize the database by creating all tables.
    Should be called when starting the application.
    """
    from sqlmodel import SQLModel
    SQLModel.metadata.create_all(engine)
