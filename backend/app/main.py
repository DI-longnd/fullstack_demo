from fastapi import FastAPI, HTTPException, Depends, status
from sqlmodel import Session
from typing import List

from .database import get_session,init_db
from .models import Todo, TodoCreate, TodoResponse, TodoUpdate,UserResponse,UserCreate,User
from .security import get_password_hash,authenticate_user,create_access_token,get_current_user
from fastapi.security import OAuth2PasswordRequestForm

app = FastAPI()

# @app.on_event("startup")
# def on_startup():
#     """Initialize the database when the FastAPI app starts."""
#     init_db()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/todos/", response_model=TodoResponse, status_code=status.HTTP_201_CREATED)
async def create_todo(
    todo: TodoCreate,
    session: Session = Depends(get_session)
):
    """
    Create a new todo item.
    """
    db_todo = Todo.from_orm(todo)
    session.add(db_todo)
    session.commit()
    session.refresh(db_todo)
    return db_todo

@app.get("/todos/", response_model=List[TodoResponse])
async def get_todos(
    skip: int = 0,
    limit: int = 100,
    session: Session = Depends(get_session)
):
    """
    Get all todos with pagination support.
    """
    todos = session.query(Todo).offset(skip).limit(limit).all()
    return todos

@app.get("/todos/{todo_id}", response_model=TodoResponse)
async def get_todo(
    todo_id: int,
    session: Session = Depends(get_session)
):
    """
    Get a specific todo by ID.
    """
    todo = session.get(Todo, todo_id)
    if not todo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Todo with id {todo_id} not found"
        )
    return todo


@app.put("/todos/{todo_id}", response_model=TodoResponse)
async def update_todo(
    todo_id: int,
    todo_update: TodoUpdate,
    session: Session = Depends(get_session)
):
    """
    Partially update a todo item. Only provided fields will be updated.
    """
    db_todo = session.get(Todo, todo_id)
    if not db_todo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Todo with id {todo_id} not found"
        )

    todo_data = todo_update.dict(exclude_unset=True)
    for key, value in todo_data.items():
        setattr(db_todo, key, value)

    # update the updated_at timestamp if present on model
    if hasattr(db_todo, "updated_at"):
        from datetime import datetime
        db_todo.updated_at = datetime.utcnow()

    session.add(db_todo)
    session.commit()
    session.refresh(db_todo)
    return db_todo


@app.delete("/todos/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(
    todo_id: int,
    session: Session = Depends(get_session)
):
    """
    Delete a todo by ID.
    """
    db_todo = session.get(Todo, todo_id)
    if not db_todo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Todo with id {todo_id} not found"
        )
    session.delete(db_todo)
    session.commit()

@app.post("/user/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserCreate,
    session: Session = Depends(get_session)
):
    """
    Register a new user.
    """
    db_user = session.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    

    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        is_active=True
    )

    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user






@app.get("/user/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_my_profile(
    ## Get my profile info from the token
    current_user : User =Depends(get_current_user)
):
    """
    Get the profile of the currently authenticated user.
    """
    return current_user
    



@app.get("/user/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    session: Session = Depends(get_session)
):
    """
    Get a specific user by ID.
    """
    user = session.get(User, user_id)
    if not user:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found")
    
    return user

@app.get("/users/get_users_by_name", response_model=List[UserResponse])
async def get_users_by_name(
    name: str,
    session: Session = Depends(get_session)
):
    """
    Get users by full name (case-insensitive search).
    """
    user = session.query(User).filter(User.full_name.ilike(f"%{name}%")).all()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Users with name containing '{name}' not found")
    return user



@app.post("/gen_token")
async def generate_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    '''  
    User send form data to get JWT token
    '''

    user = await authenticate_user(
        username=form_data.username, 
        password=form_data.password, 
        session=session
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})

    return {"access_token": access_token, "token_type": "bearer"}





if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    