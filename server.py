"""
SecureVault Backend API
FastAPI server for cross-device password sync

Security: Zero-knowledge architecture - server only stores encrypted data
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import aiosqlite
import os
import secrets
import hashlib
import httpx

# ==================== CONFIG ====================

DATABASE_PATH = "securevault.db"
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# ==================== APP SETUP ====================

app = FastAPI(
    title="SecureVault API",
    description="Secure password manager backend",
    version="1.0.0"
)

# CORS - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Bearer token
security = HTTPBearer()

# ==================== MODELS ====================

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class VaultData(BaseModel):
    data: str  # Encrypted JSON string
    updated_at: str | None = None

class SyncRequest(BaseModel):
    data: str  # Encrypted vault data
    last_sync: str | None = None

class SyncResponse(BaseModel):
    data: str | None
    updated_at: str | None
    needs_sync: bool

# ==================== DATABASE ====================

async def init_db():
    """Initialize the SQLite database"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vaults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                encrypted_data TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        await db.commit()

@app.on_event("startup")
async def startup():
    await init_db()

# ==================== AUTH HELPERS ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return user ID"""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_id

# ==================== AUTH ENDPOINTS ====================

@app.post("/api/register", response_model=Token)
async def register(user: UserCreate):
    """Register a new user"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Check if email exists
        cursor = await db.execute(
            "SELECT id FROM users WHERE email = ?", (user.email,)
        )
        if await cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user
        password_hash = get_password_hash(user.password)
        cursor = await db.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (user.email, password_hash)
        )
        await db.commit()
        user_id = cursor.lastrowid
        
        # Create token
        access_token = create_access_token(data={"user_id": user_id})
        return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/login", response_model=Token)
async def login(user: UserLogin):
    """Login and get access token"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (user.email,)
        )
        row = await cursor.fetchone()
        
        if not row or not verify_password(user.password, row[1]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        access_token = create_access_token(data={"user_id": row[0]})
        return {"access_token": access_token, "token_type": "bearer"}

# ==================== VAULT ENDPOINTS ====================

@app.get("/api/vault", response_model=VaultData | None)
async def get_vault(user_id: int = Depends(get_current_user)):
    """Get user's encrypted vault data"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT encrypted_data, updated_at FROM vaults WHERE user_id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        
        if not row:
            return None
        
        return {"data": row[0], "updated_at": row[1]}

@app.put("/api/vault")
async def save_vault(vault: VaultData, user_id: int = Depends(get_current_user)):
    """Save user's encrypted vault data"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Check if vault exists
        cursor = await db.execute(
            "SELECT id FROM vaults WHERE user_id = ?", (user_id,)
        )
        exists = await cursor.fetchone()
        
        now = datetime.utcnow().isoformat()
        
        if exists:
            await db.execute(
                "UPDATE vaults SET encrypted_data = ?, updated_at = ? WHERE user_id = ?",
                (vault.data, now, user_id)
            )
        else:
            await db.execute(
                "INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)",
                (user_id, vault.data, now)
            )
        
        await db.commit()
        return {"status": "ok", "updated_at": now}

@app.post("/api/sync", response_model=SyncResponse)
async def sync_vault(sync: SyncRequest, user_id: int = Depends(get_current_user)):
    """
    Sync vault data between client and server.
    Returns server data if it's newer, otherwise saves client data.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT encrypted_data, updated_at FROM vaults WHERE user_id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        
        now = datetime.utcnow().isoformat()
        
        if not row:
            # No server data, save client data
            await db.execute(
                "INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)",
                (user_id, sync.data, now)
            )
            await db.commit()
            return {"data": None, "updated_at": now, "needs_sync": False}
        
        server_data, server_updated = row
        
        # Compare timestamps
        if sync.last_sync:
            client_time = datetime.fromisoformat(sync.last_sync)
            server_time = datetime.fromisoformat(server_updated)
            
            if server_time > client_time:
                # Server has newer data
                return {"data": server_data, "updated_at": server_updated, "needs_sync": True}
        
        # Client data is newer or same, update server
        await db.execute(
            "UPDATE vaults SET encrypted_data = ?, updated_at = ? WHERE user_id = ?",
            (sync.data, now, user_id)
        )
        await db.commit()
        return {"data": None, "updated_at": now, "needs_sync": False}

@app.delete("/api/vault")
async def delete_vault(user_id: int = Depends(get_current_user)):
    """Delete user's vault data"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("DELETE FROM vaults WHERE user_id = ?", (user_id,))
        await db.commit()
        return {"status": "ok"}

# ==================== USER ENDPOINTS ====================

@app.get("/api/me")
async def get_me(user_id: int = Depends(get_current_user)):
    """Get current user info"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT email, created_at FROM users WHERE id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {"email": row[0], "created_at": row[1]}

@app.delete("/api/me")
async def delete_account(user_id: int = Depends(get_current_user)):
    """Delete user account and all data"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("DELETE FROM vaults WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
        return {"status": "ok"}

# ==================== SECURITY ENDPOINTS ====================

class BreachCheckRequest(BaseModel):
    password_hash_prefix: str  # First 5 chars of SHA-1 hash

@app.post("/api/check-breach")
async def check_breach(request: BreachCheckRequest):
    """
    Check if a password has been in a data breach using HaveIBeenPwned API.
    Client sends first 5 characters of SHA-1 hash (k-anonymity).
    """
    prefix = request.password_hash_prefix.upper()
    if len(prefix) != 5:
        raise HTTPException(status_code=400, detail="Hash prefix must be 5 characters")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "SecureVault-PasswordManager"}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail="Breach API unavailable")
            
            # Return the list of hash suffixes and counts
            return {"suffixes": response.text}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to check breach: {str(e)}")

# ==================== STATIC FILES ====================

# Serve the PWA frontend
app.mount("/", StaticFiles(directory=".", html=True), name="static")

# ==================== RUN ====================

if __name__ == "__main__":
    import uvicorn
    import ssl
    import sys
    
    # Check for SSL certificates
    ssl_cert = "cert.pem"
    ssl_key = "key.pem"
    
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        print("🔒 Starting HTTPS server with SSL...")
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=8443,
            ssl_keyfile=ssl_key,
            ssl_certfile=ssl_cert
        )
    else:
        print("⚠️  SSL certificates not found, starting HTTP server...")
        print("   Run: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes")
        uvicorn.run(app, host="0.0.0.0", port=8080)

