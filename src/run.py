import uvicorn
from .main import app


def run():
    uvicorn.run(app, host="0.0.0.0", port=5000, use_colors=True)
