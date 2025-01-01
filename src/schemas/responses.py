from fastapi.responses import JSONResponse


class CustomJSONResponse(JSONResponse):
    def __init__(
        self,
        success: bool,
        status_code: int,
        message: str,
        data: dict | None = None,
        error: dict | None = None,
        meta: dict | None = None,
        **kwargs
    ):
        """
        Initializes the custom JSON response with the provided parameters.

        # Args:
            `success` (bool): Whether the request was successful or not.
            `status_code` (int): HTTP status code of the response.
            `message` (str): A short message describing the response.
            `data` (dict | None): The actual data payload (optional).
            `error` (dict | None): Error details, if any (optional).
            `meta` (dict | None): Additional metadata, if any (optional).
            `**kwargs`: Additional arguments passed to the parent JSONResponse.

        # Returns:
            `CustomJSONResponse:` A JSON response with a dict and the provided HTTP status code.
        """
        content = {
            "success": success,
            "status_code": status_code,
            "message": message,
            "data": data,
            "error": error,
            "meta": meta,
        }
        super().__init__(content=content, status_code=status_code, **kwargs)


class CustomBackendErrorResponse(JSONResponse):
    def __init__(self, **kwargs):
        """
        Initializes the custom JSON response with the provided parameters.

        # Args:
            `**kwargs`: Additional arguments passed to the parent JSONResponse.

        # Returns:
            `CustomBackendErrorResponse:` A JSON response with a dict and HTTP status code 500.
        """
        content = {
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
        super().__init__(content=content, status_code=500, **kwargs)
