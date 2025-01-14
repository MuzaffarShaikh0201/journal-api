import os
import json
from sqlalchemy import text
from typing import Any, Dict, Tuple
from fastapi import FastAPI, HTTPException, Request
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from .routes import utility, auth, user
from .core.config import settings
from .middleware.logging import logger
from .database.connect import temp_session
from .middleware.rate_limitter import RateLimitMiddleware, rate_limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting application...")
    try:
        logger.info("Connecting to the database...")

        with temp_session() as session:
            session.execute(text("SELECT 1"))
            session.close()

        logger.info("Connected to the database successfully.")

        if not os.path.isdir("keys"):
            os.makedirs("keys")

            settings.download_keys()
            logger.info("Keys downloaded successfully.")

        logger.info("Application started successfully.")
        yield
    except Exception as e:
        logger.error(f"Failed to connect to the database: {e}")
        raise e
    finally:
        logger.info("Application stopped successfully.")


app = FastAPI(lifespan=lifespan)

# Set up CORS (Cross-Origin Resource Sharing)
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=[
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Connection",
        "Connection-Length",
        "Connection-Type",
        "Keep-Alive",
        "Content-Length",
        "Content-Type",
        "Cookie",
        "Date",
        "Host",
        "Origin",
        "Referer",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "User-Agent",
        "Sec-Ch-Ua-Mobile",
        "Sec-Ch-Ua-Platform",
    ],
)

# Global Rate Limiting Middleware
app.add_middleware(
    RateLimitMiddleware,
    rate_limiter=rate_limiter,
    limit=10,  # Maximum 10 requests
    window=60,  # Per 60 seconds
)


# Routes
app.include_router(utility.router)
app.include_router(auth.router)
app.include_router(user.router)


# Custom validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = [
        {"field": ".".join(e["loc"]), "error": e["msg"]} for e in exc.errors()
    ]
    response = {
        "success": False,
        "status_code": 422,
        "message": "Validation Error(s)",
        "data": None,
        "error": {"code": "VALIDATION_ERROR", "details": error_details},
        "meta": None,
    }
    return JSONResponse(status_code=422, content=response)


# Custom handler for internal server errors
@app.exception_handler(Exception)
async def internal_server_error_handler(request: Request, exc: Exception):
    # Log the error for debugging (optional)
    logger.error(f"Unexpected error: {exc}", exc_info=True)

    # Standardized response for 500 errors
    response = {
        "success": False,
        "status_code": 500,
        "message": "Internal Server Error",
        "data": None,
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "details": "An unexpected error occurred. Please try again later.",
        },
        "meta": None,
    }
    return JSONResponse(status_code=500, content=response)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTPException: {exc.detail}")

    return JSONResponse(
        status_code=exc.status_code, content=exc.detail, headers=exc.headers
    )


# Custom OpenAPI schema metadata
summary = "Backend services for Journal App."
description = (
    "`Apart from the response codes specified in each API, the API server may respond with other common "
    "responses based on standard API behavior.`"
)

tags_metadata = [
    {
        "name": "Utility APIs",
        "description": (
            "The Utility APIs contain endpoints that serve operational or system-level purposes. "
            "These routes are not directly related to the core business logic of the API but "
            "are essential for overall functionality, monitoring, and accessibility."
        ),
    },
    {
        "name": "Auth APIs",
        "description": (
            "The Auth APIs are used for user authentication and authorization. "
            "These endpoints handle user login, registration, and logout functionalities."
        ),
    },
]


# Helper function to extract headers and payload from OpenAPI operation
def extract_headers_and_payload(
    operation: Dict[str, Any], components: Dict[str, Any]
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    headers = {
        param["name"]: (
            param["schema"].get("type")
            or (
                "Bearer <token>"
                if param["name"] == "Authorization"
                else " | ".join(v["type"] for v in param["schema"].get("anyOf", []))
            )
        )
        for param in operation.get("parameters", [])
        if param.get("in") == "header"
    }

    payload_example = {}
    request_body = operation.get("requestBody", {}).get("content", {})
    for content_type, content in request_body.items():
        if content_type in ("application/json", "application/x-www-form-urlencoded"):
            headers["Content-Type"] = content_type
            schema_ref = content["schema"].get("$ref", "")
            schema_name = schema_ref.split("/")[-1] if schema_ref else None
            if schema_name:
                properties = (
                    components["schemas"].get(schema_name, {}).get("properties", {})
                )
                for key, value in properties.items():
                    if "anyOf" in value:
                        payload_example[key] = " | ".join(
                            v["type"] for v in value["anyOf"]
                        )
                    else:
                        payload_example[key] = value.get("type", "")
    return headers, payload_example


# Helper function to generate code samples
def generate_code_samples(
    path: str, method: str, operation: Dict[str, Any], components: Dict[str, Any]
) -> None:
    nl = "\n"
    tl = "    "
    base_url = settings.BASE_URL

    headers, payload_example = extract_headers_and_payload(operation, components)

    # Constructing query string
    query_params = [
        param for param in operation.get("parameters", []) if param.get("in") == "query"
    ]
    query_string = "&".join(f"{param['name']}={{value}}" for param in query_params)
    query_string = f"?{query_string}" if query_string else ""

    # Generating cURL example
    curl_headers = "".join(f"{tl}-H '{k}: {v}'{nl}" for k, v in headers.items())
    curl_payload = (
        f"{tl}-d '{json.dumps(payload_example)}'{nl}" if payload_example else ""
    )
    curl_sample = (
        f"curl -X {method.upper()} {base_url}{path}{query_string}{nl}"
        f"{curl_headers}{curl_payload}"
    ).strip()

    # Generating Python example
    python_sample = (
        f"import requests{nl}import json{nl}{nl}"
        f"url = '{base_url}{path}{query_string}'{nl}"
        f"payload = {json.dumps(payload_example) if payload_example else {}}{nl}"
        f"headers = {json.dumps(headers)}{nl}{nl}"
        f"response = requests.{method.lower()}(url, headers=headers, json=payload){nl}"
        f"print(response.text)"
    )

    operation["x-code-samples"] = [
        {"lang": "curl", "source": curl_sample, "label": "Curl"},
        {"lang": "Python", "source": python_sample, "label": "Python3"},
    ]


# Custom OpenAPI schema generator
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Journal App API",
        version="1.0.0",
        summary=summary,
        description=description,
        tags=tags_metadata,
        routes=app.routes,
        contact={"name": "Muzaffar Shaikh", "email": "muzaffarshaikh0201@gmail.com"},
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png",
    }

    components = openapi_schema.get("components", {})
    for path, path_item in openapi_schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if path == "/auth/register" and method == "post":
                operation["responses"].pop("200", None)
            if method in {"get", "post", "put", "delete", "patch"}:
                generate_code_samples(path, method, operation, components)

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Seting the custom OpenAPI function
app.openapi = custom_openapi
