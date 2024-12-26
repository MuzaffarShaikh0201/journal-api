import json
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings

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
@app.get("/")
async def root():
    return {"message": "Hello World"}


# Custom OpenAPI schema
summary = "Journal API"
description = "Backend services for Journal App."

tags_metadata = [
    {
        "name": "Miscellaneous",
        "description": "Utility APIs",
    }
]


def get_code_samples(route, method):
    nl = "\n"  # new line character to use in f-strings.
    header = {}
    cookies = {}
    BASE_URL = settings.BASE_URL

    if method in ["POST", "PUT", "DELETE", "GET"]:
        try:
            if route.body_field:
                example_schema = getattr(route.body_field.type_, "Config", None)
                if example_schema:
                    example_schema = example_schema.schema_extra.get("example", {})
                else:
                    example_schema = {}
            else:
                example_schema = {}

            payload = f"json.dumps({example_schema})"
            data_raw = (
                f"\\{nl} --data-raw " + "'" + f"{json.dumps(example_schema)} " + "'"
            )
        except Exception as e:
            print(f"Path:{route.path} Error:{e}")
            payload = "{}"
            data_raw = ""

    else:
        payload = "{}"
        data_raw = ""

    return [
        {
            "lang": "Shell",
            "source": f"curl --location\\{nl} "
            f"--request {method} '{BASE_URL}{route.path}'\\{nl} "
            f"--header {header}"
            f"--cookie {cookies}{nl}"
            f"{data_raw}",
            "label": "Curl",
        },
        {
            "lang": "Python",
            "source": f"import requests{nl}"
            f"{'import json' + nl if method.lower() == 'post' else ''}{nl}"
            f'url = "{BASE_URL}{route.path}"{nl}'
            f"payload = {payload}{nl}"
            f"headers = {header}{nl}"
            f"cookies = {cookies}{nl}"
            f'response = requests.request("{method}", url, headers=headers, data=payload){nl}'
            f"print(response.text)",
            "label": "Python3",
        },
    ]


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
