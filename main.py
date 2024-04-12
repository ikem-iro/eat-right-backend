from fastapi import FastAPI
from routes.users_route import router

app = FastAPI()

def create_app():
    """
    Creates and configures the FastAPI application.

    This function initializes the FastAPI application and includes the user routes.

    Returns:
        FastAPI: The configured FastAPI application instance.
    """
    app = FastAPI()
    app.include_router(router)
    return app

app = create_app()