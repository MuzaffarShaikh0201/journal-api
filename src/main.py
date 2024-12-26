import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from .routes import home
from .core.config import settings
from .middleware.logging import logger

app = FastAPI()


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


# Routes
app.include_router(home.router)


# Custom validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = [
        {"field": ".".join(e["loc"]), "error": e["msg"]} for e in exc.errors()
    ]
    response = {
        "success": False,
        "status_code": 422,
        "message": "Validation Error",
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


# Custom OpenAPI schema metadata
summary = "Backend services for Journal App."
description = "`Apart from the response codes specified in each API, the API server may respond with certain 4xx and 5xx error codes which are related to common API Gateway behaviors.`"

tags_metadata = [
    {
        "name": "Utility APIs",
        "description": "The Utility APIs contain endpoints that serve operational or system-level purposes. These routes are not directly related to the core business logic of the API but are essential for overall functionality, monitoring, and accessibility.",
    }
]


# Helper function to generate code samples for curl and Python
def get_code_samples(route, method):
    nl = "\n"  # new line character to use in f-strings.
    header = {"Content-Type": "application/json"}  # Default header for JSON payload
    cookies = {}
    BASE_URL = settings.BASE_URL

    # Check if the method is one that supports body (POST, PUT, DELETE, GET)
    if method in ["POST", "PUT", "DELETE", "PATCH", "GET"]:
        try:
            # Check if the route has a body schema to generate an example
            if route.body_field:
                example_schema = getattr(route.body_field.type_, "Config", None)
                if example_schema:
                    example_schema = example_schema.schema_extra.get("example", {})
                else:
                    example_schema = {}
            else:
                example_schema = {}

            # Prepare the payload
            payload = json.dumps(example_schema) if example_schema else "{}"
            data_raw = f"--data-raw '{payload}'" if example_schema else ""
        except Exception as e:
            print(f"Path:{route.path} Error:{e}")
            payload = "{}"
            data_raw = ""
    else:
        payload = "{}"
        data_raw = ""

    # Construct cURL and Python code samples
    curl_sample = f"curl --location {nl} --request {method} '{BASE_URL}{route.path}' {nl} --header 'Content-Type: application/json' {nl} {data_raw}"

    python_sample = f"""import requests
        import json
        url = '{BASE_URL}{route.path}'
        payload = {json.dumps(example_schema)}  # JSON payload
        headers = {json.dumps({'Content-Type': 'application/json'})}
        response = requests.request('{method}', url, headers=headers, data=payload)
        print(response.text)
        """

    return [
        {
            "lang": "Shell",
            "source": curl_sample,
            "label": "Curl",
        },
        {
            "lang": "Python",
            "source": python_sample,
            "label": "Python3",
        },
    ]


# Custom OpenAPI schema function
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version=settings.API_VERSION,
        summary=summary,
        description=description,
        tags=tags_metadata,
        routes=app.routes,
        contact={
            "name": "Muzaffar Shaikh",
            "email": "muzaffarshaikh0201@gmail.com",
        },
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }

    for route in app.routes:
        if (
            ".json" not in route.path
            and ".yaml" not in route.path
            and "/docs" not in route.path
            and "/docs/oauth2-redirect" not in route.path
            and "/redoc" not in route.path
        ):
            for method in route.methods:
                if method.lower() in openapi_schema["paths"][route.path]:
                    code_samples = get_code_samples(route=route, method=method)
                    openapi_schema["paths"][route.path][method.lower()][
                        "x-codeSamples"
                    ] = code_samples

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
