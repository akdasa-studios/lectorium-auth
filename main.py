from fastapi import FastAPI, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from user import get_user_data, get_password_hash
import jwt

# Load RSA keys
with open("private_key.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public_key.pem", "r") as f:
    PUBLIC_KEY = f.read()

# Constants
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# OAuth2 dependency for token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic model for token response
class Token(BaseModel):
    access_token: str
    token_type: str

# Function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# HTML form for login
login_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form action="/auth/login" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.get("/auth", response_class=HTMLResponse)
async def login_form():
    """Display the login form."""
    return login_html

@app.post("/auth/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # Check if user exists
    user = get_user_data(
        server_url="http://lectorium:lectorium@database:5984", # TODO: Get from env
        username=username
    )
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Check if password is correct
    hashed_password = get_password_hash(
        pwd=password,
        salt=user["salt"],
        iterations=user["iterations"],
    )
    if hashed_password != user["derived_key"]:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # User is authenticated, create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": username,
            "_couchdb.roles": user["roles"]
        }, expires_delta=access_token_expires
    )
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(key="Authorization", value=access_token, httponly=True)
    return response

# Protected route to check authentication
@app.get("/auth/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    """Sample protected route that checks for the JWT token."""
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"message": f"Hello, {username}"}
