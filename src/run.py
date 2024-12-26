import uvicorn
from .main import app


def run():
    uvicorn.run(app, host="0.0.0.0", port=5000, use_colors=True)


def dev():
    uvicorn.run(app="src.main:app", port=5000, reload=True, use_colors=True)
