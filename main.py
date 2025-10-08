from fastapi import FastAPI
from db import engine, Base
from routers import auth, products, favorites, lists, alerts
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title='PRICEZAPP Backend (Auth Ready)')

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(auth.router)
app.include_router(products.router)
app.include_router(favorites.router)
app.include_router(lists.router)
app.include_router(alerts.router)

@app.get('/')
def root():
    return {'message':'PRICEZAPP backend (auth) running'}
