from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Any
import os
from supabase import create_client, Client
from datetime import datetime, timedelta
import jwt
from jwt import PyJWTError
from passlib.context import CryptContext

app = FastAPI(title="Pricezapp API")

# CORS para permitir tu frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://tu-frontend.onrender.com",  # Tu futuro dominio
        "http://localhost:8000",  # Para desarrollo local
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://mkqrkjjalxvyibpqjrtt.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1rcXJramphbHh2eWlicHFqcnR0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTk5MzI4MTMsImV4cCI6MjA3NTUwODgxM30.PxHR2fUQkz_2JHuYH4nZ1qzKEUVTSs9PMTxZIxjbayo")
SECRET_KEY = os.getenv("SECRET_KEY", "pricezapp-super-secret-key-2024-ultra-segura")
ALGORITHM = "HS256"

# Inicializar Supabase
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Conexión a Supabase exitosa")
except Exception as e:
    print(f"❌ Error conectando a Supabase: {e}")
    supabase = None

# Configuración de passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modelos de datos
class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class FavoriteCreate(BaseModel):
    product_id: int
    product_data: Optional[dict] = None

class ShoppingListCreate(BaseModel):
    name: str

class ShoppingListItemCreate(BaseModel):
    list_id: int
    product_id: int
    product_data: dict
    quantity: int = 1

class PriceAlertCreate(BaseModel):
    product_id: int
    target_price: float

# Funciones de autenticación
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(authorization: str = Header(None)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not authorization:
        raise credentials_exception
    
    try:
        # Extraer el token del header "Bearer {token}"
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
            
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
            
    except (ValueError, PyJWTError):
        raise credentials_exception
    
    # Verificar que el usuario existe en Supabase
    if supabase:
        user_data = supabase.table("users").select("*").eq("id", user_id).execute()
        if not user_data.data:
            raise credentials_exception
    
    return user_id

# Endpoints de autenticación
@app.post("/auth/register")
async def register(user: UserRegister):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        # Verificar si el usuario ya existe
        existing_user = supabase.table("users").select("*").eq("email", user.email).execute()
        if existing_user.data:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Crear usuario
        hashed_password = get_password_hash(user.password)
        new_user = supabase.table("users").insert({
            "email": user.email,
            "password_hash": hashed_password,
            "name": user.name,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        if not new_user.data:
            raise HTTPException(status_code=500, detail="Error creating user")
        
        # Crear token
        access_token = create_access_token(data={"user_id": new_user.data[0]["id"]})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": new_user.data[0]["id"],
                "email": user.email,
                "name": user.name
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login")
async def login(user: UserLogin):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        # Buscar usuario
        user_data = supabase.table("users").select("*").eq("email", user.email).execute()
        if not user_data.data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        db_user = user_data.data[0]
        
        # Verificar password
        if not verify_password(user.password, db_user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Crear token
        access_token = create_access_token(data={"user_id": db_user["id"]})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": db_user["id"],
                "email": db_user["email"],
                "name": db_user["name"]
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de favoritos
@app.post("/favorites/")
async def add_favorite(favorite: FavoriteCreate, user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        favorite_data = {
            "user_id": user_id,
            "product_id": favorite.product_id,
            "product_data": favorite.product_data,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("favorites").insert(favorite_data).execute()
        return {"message": "Favorite added", "favorite_id": result.data[0]["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/favorites/")
async def get_favorites(user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        favorites = supabase.table("favorites").select("*").eq("user_id", user_id).execute()
        return favorites.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/favorites/{product_id}")
async def remove_favorite(product_id: int, user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        supabase.table("favorites").delete().eq("user_id", user_id).eq("product_id", product_id).execute()
        return {"message": "Favorite removed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de listas de compras
@app.post("/shopping-lists/")
async def create_shopping_list(list_data: ShoppingListCreate, user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        list_obj = {
            "user_id": user_id,
            "name": list_data.name,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("shopping_lists").insert(list_obj).execute()
        return {"message": "List created", "list_id": result.data[0]["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/shopping-lists/")
async def get_shopping_lists(user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        lists = supabase.table("shopping_lists").select("*").eq("user_id", user_id).execute()
        return lists.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/shopping-lists/items")
async def add_to_shopping_list(item: ShoppingListItemCreate, user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        # Verificar que la lista pertenece al usuario
        list_data = supabase.table("shopping_lists").select("*").eq("id", item.list_id).eq("user_id", user_id).execute()
        if not list_data.data:
            raise HTTPException(status_code=404, detail="List not found")
        
        item_data = {
            "list_id": item.list_id,
            "product_id": item.product_id,
            "product_data": item.product_data,
            "quantity": item.quantity,
            "added_at": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("shopping_list_items").insert(item_data).execute()
        return {"message": "Item added to list", "item_id": result.data[0]["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de alertas de precio
@app.post("/price-alerts/")
async def create_price_alert(alert: PriceAlertCreate, user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        alert_data = {
            "user_id": user_id,
            "product_id": alert.product_id,
            "target_price": alert.target_price,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("price_alerts").insert(alert_data).execute()
        return {"message": "Price alert created", "alert_id": result.data[0]["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/price-alerts/")
async def get_price_alerts(user_id: int = Depends(get_current_user)):
    try:
        if not supabase:
            raise HTTPException(status_code=500, detail="Database connection error")
            
        alerts = supabase.table("price_alerts").select("*").eq("user_id", user_id).execute()
        return alerts.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Health check
@app.get("/")
async def root():
    return {"message": "Pricezapp API is running!", "timestamp": datetime.utcnow().isoformat()}

@app.get("/health")
async def health_check():
    db_status = "connected" if supabase else "disconnected"
    return {
        "status": "healthy", 
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/test-supabase")
async def test_supabase():
    try:
        if supabase:
            # Intentar una consulta simple
            result = supabase.table("users").select("count", count="exact").execute()
            return {"message": "Supabase connection successful", "count": result.count}
        else:
            return {"message": "Supabase not initialized"}
    except Exception as e:
        return {"message": f"Supabase error: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
