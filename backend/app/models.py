from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    full_name: Optional[str] = None
    hashed_password: str
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(SQLModel):
    username: str
    email: str
    full_name: Optional[str] = None
    password: str

class UserResponse(SQLModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    created_at: datetime

class TodoBase(SQLModel):
    title: str = Field(index=True)
    description: Optional[str] = Field(default=None)
    is_completed: bool = Field(default=False)
    priority: int = Field(default=1, ge=1, le=5)  # Priority from 1-5
    due_date: Optional[datetime] = Field(default=None)

class Todo(TodoBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

class TodoCreate(TodoBase):
    pass

class TodoUpdate(SQLModel):
    title: Optional[str] = None
    description: Optional[str] = None
    is_completed: Optional[bool] = None
    priority: Optional[int] = None
    due_date: Optional[datetime] = None

class TodoResponse(TodoBase):
    id: int
    created_at: datetime
    updated_at: datetime
