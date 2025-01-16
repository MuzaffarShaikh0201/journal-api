from fastapi import HTTPException
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


class CustomHttpException(HTTPException):
    def __init__(
        self,
        status_code: int,
        message: str,
        error_code: str,
        error_details: str,
        headers: dict = None,
        **kwargs
    ):
        """
        Initializes the custom HTTP exception with the provided parameters.

        # Args:
            `status_code` (int): HTTP status code of the response.
            `message` (str): A short message describing the response.
            `error_code` (str): A unique error code for the exception.
            `error_details` (str): Details about the error.

        # Returns:
            `CustomHttpException:` An HTTP exception with the provided status code and message.
        """
        detail = {
            "success": False,
            "status_code": status_code,
            "message": message,
            "data": None,
            "error": {
                "code": error_code,
                "details": error_details,
            },
            "meta": None,
        }

        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}

        super().__init__(
            status_code=status_code, detail=detail, headers=headers, **kwargs
        )
