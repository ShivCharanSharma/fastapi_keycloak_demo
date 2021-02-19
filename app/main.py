from fastapi import Depends, FastAPI, HTTPException,status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from typing import Optional
from keycloak import KeycloakOpenID
from config import Config

app = FastAPI()

keycloak_openid = KeycloakOpenID(
    server_url= Config["server_url"],
    client_id=Config["client_id"], 
    realm_name=Config["realm_name"],
    client_secret_key=Config["client_secret_key"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

async def decode_token(token:str= Depends(oauth2_scheme)):

    try:
        KEYCLOAK_PUBLIC_KEY =(
            "-----BEGIN PUBLIC KEY-----\n"
            +
            keycloak_openid.public_key()
            +
            "\n-----END PUBLIC KEY-----"
        )
        return keycloak_openid.decode_token(
            token,
            key=KEYCLOAK_PUBLIC_KEY,
            options={"verify_signature":True,"verify_aud":False,"exp":True},
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate":"Bearer"},
        )


async def get_current_user(user: dict = Depends(decode_token)):
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user




@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    
    try:
        token = keycloak_openid.token(form_data.username, form_data.password)
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


@app.get("/users/me")
async def read_users_me(current_user: dict =Depends(get_current_user)):
    return current_user

