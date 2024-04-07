from fastapi import FastAPI
from routes import users_route



app = FastAPI()




app.include_router(users_route.router, prefix="/v1")




