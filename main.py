from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from user import get_user_data, get_password_hash
import jwt
from fastapi import Request
import os

ALGORITHM = "RS256"

# ---------------------------------------------------------------------------- #
#                                   Read Data                                  #
# ---------------------------------------------------------------------------- #

with open("keys/jwt_private_key.pem", "r") as f:
    PRIVATE_KEY = f.read()
with open("keys/jwt_public_key.pem", "r") as f:
    PUBLIC_KEY = f.read()
with open("templates/sign-in.html", "r") as f:
  login_html = f.read()
with open("templates/signed-in.html", "r") as f:
  signed_in_html = f.read()

DATABASE_CONNECTION_STRING = os.getenv(
    "DATABASE_CONNECTION_STRING",
    "http://lectorium:lectorium@database:5984"
)
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
)

# ---------------------------------------------------------------------------- #
#                                      App                                     #
# ---------------------------------------------------------------------------- #

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str


# ---------------------------------------------------------------------------- #
#                                    Helpers                                   #
# ---------------------------------------------------------------------------- #

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ---------------------------------------------------------------------------- #
#                                   Endpoints                                  #
# ---------------------------------------------------------------------------- #

@app.get("/auth", response_class=HTMLResponse)
async def login_form():
    return login_html

@app.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    # Check if user exists
    user = get_user_data(
        server_url="http://lectorium:lectorium@database:5984", # TODO: Get from env
        username=username
    )
    if user is None:
        if request.headers.get("accept") == "application/json":
            raise HTTPException(status_code=400, detail="Invalid credentials")
        else:
            return HTMLResponse(content=login_html)

    # Check if password is correct
    hashed_password = get_password_hash(
        pwd=password,
        salt=user["salt"],
        iterations=user["iterations"],
    )
    if hashed_password != user["derived_key"]:
        if request.headers.get("accept") == "application/json":
            raise HTTPException(status_code=400, detail="Invalid credentials")
        else:
            return HTMLResponse(content=login_html)

    # User is authenticated, create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": username,
            "_couchdb.roles": user["roles"]
        }, expires_delta=access_token_expires
    )

    if request.headers.get("accept") == "application/json":
        response = JSONResponse(content={"message": "Login successful"})
    else:
        response = HTMLResponse(content=signed_in_html)

    response.set_cookie(key="Authorization", value=access_token, httponly=True)
    return response
