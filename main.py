#!/usr/bin/env python3
"""
Fill me in later.
"""

import logging
import uuid

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.testclient import TestClient
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


# Crypt things. THese are all demo values.
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

# Configure Logging
logging.basicConfig(
    # level = logging.DEBUG
    level = logging.INFO
)


# Set up FastAPI app and other aux things.
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Fake/Mock values
mock_db = {}
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False
    },
    "fired-admin": {
        "username": "fired-admin",
        "hashed_password": "fakehashedsecret2",
        "disabled": True
    }
}


class Token(BaseModel):
    """
    Model of a token presented to the client.
    """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """
    TODO: Dig more.
    """
    username: str | None = None


class User(BaseModel):
    """
    Model that describes a user of the API to generate tokens.
    """
    username: str
    disabled: bool | None = None


class UserInDB(User):
    """
    Child model that describes a User that exists in the databsae.
    """
    hashed_password: str


def verify_password(plain_password, hashed_password):
    """
    Verify the incoming password matches the stored hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    Hash the incoming password.
    """
    return pwd_context.hash(password)


def get_user(db, username: str):
    """
    Discover if the user exists in the DB. If so, we return a UserInDB type
    that will have the hashed password in addition to the usual attributes.

    Note that this only works for Fake/MockDB at the moment.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """
    Authentication flow for a user.
    """
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Generate a JWT.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Figures out if the current token is valid. If so, return a UserInDB object.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]):
    """
    Figures out if the current user is disabled or not.

    Depends on get_current_user which in turn means a valid token.
    """

    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


class TokenId(BaseModel):
    """"
    TODO
    """
    host: str
    id: str
    token: str

class TokenRequest(BaseModel):
    """
    TODO
    """
    host: str


@app.get("/")
async def get_root():
    """
    Root route.
    """
    return {"message": "Hello World"}


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Endpoint to login with username/password and obtain a JWT.
    """
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/tokens")
async def get_tokens(token: Annotated[str, Depends(get_current_user)]):
    """
    TODO
    """
    return {"tokens": mock_db}


@app.post("/tokens")
async def create_token(request: TokenRequest):
    """
    TODO
    """
    logging.info(f"Creating a token for {request.host}")

    new_token_id = str(uuid.uuid4())

    # This is a holder. We need to actually do all the hashing and whatnot.
    # Also it won't be a uuid in the end state. It will be a jwt as we want to
    # use short lived tokens.
    new_token = str(uuid.uuid4())

    new_token = TokenId(
        host = request.host,
        id = new_token_id,
        token = new_token,
    )

    logging.debug(f"New Token: {new_token}")

    # Search DB for duplicate ID
    # Write to DB
    mock_db[new_token.id] = new_token

    # Handle errors

    return {"message": "success"}


@app.get("/users/me")
async def get_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Return data about ourself.
    """
    return current_user


# Tests
client = TestClient(app)

def test_get_root():
    """
    Unit test the root route.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}

def test_create_token():
    """
    Unit test creating a DNS consumer token.
    """
    response = client.post(
        "/tokens",
        headers={"X-Blah": "Blah"},
        json={"host": "sheep.t0fu.dev"},
    )
    print(f"Response is: {response.content}")
    assert response.status_code == 200
    assert response.json() == {"message": "success"}
