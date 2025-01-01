import re
from typing import Annotated
from fastapi import Form, Header
from pydantic import EmailStr, SecretStr
from fastapi.exceptions import RequestValidationError


def validate_password(password: SecretStr) -> SecretStr:
    """
    Validate password for the following conditions:
    - At least one number
    - At least one special character
    - At least one alphabet

    ## Args:
        `password` (SecretStr): Password to be validated

    ## Returns:
        SecretStr: Password if all conditions are met

    ## Raises:
        `RequestValidationError`: If any of the conditions are not met
    """
    password_value = password.get_secret_value()  # Extract plain password
    errors = []

    # At least one number
    if not re.search(r"\d", password_value):
        errors.append(
            {
                "type": "missing_number",
                "loc": ("body", "password"),
                "msg": "Value should have at least one number",
                "input": password_value,
            }
        )

    # At least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_value):
        errors.append(
            {
                "type": "missing_special_char",
                "loc": ("body", "password"),
                "msg": "Value should have at least one special character",
                "input": password_value,
            }
        )

    # At least one alphabet
    if not re.search(r"[a-zA-Z]", password_value):
        errors.append(
            {
                "type": "missing_alphabet",
                "loc": ("body", "password"),
                "msg": "Value should have at least one alphabet",
                "input": password_value,
            }
        )

    # Raise validation error if any of the conditions are not met
    if errors:
        raise RequestValidationError(errors)

    return password


def validate_name(name: str, field_name: str) -> str:
    """
    Validate name for the following conditions:
    - Should not contain spaces
    - Should only contain alphabets

    ## Args:
        `name` (str): Name to be validated
        `field_name` (str): Field name to be used in the error message

    ## Returns:
        str: Name if all conditions are met

    ## Raises:
        `RequestValidationError`: If any of the conditions are not met
    """
    errors = []

    # Should not contain spaces
    if re.search(r"\s", name):
        errors.append(
            {
                "type": "invalid_name",
                "loc": ("body", field_name),
                "msg": "Name should not contain spaces",
                "input": name,
            }
        )

    # Should only contain alphabets
    if re.search(r"[^a-zA-Z]", name):
        errors.append(
            {
                "type": "invalid_name",
                "loc": ("body", field_name),
                "msg": "Name should only contain alphabets",
                "input": name,
            }
        )

    # Raise validation error if any of the conditions are not met
    if errors:
        raise RequestValidationError(errors)

    return name


class LoginForm:
    def __init__(
        self,
        email: EmailStr = Form(
            ...,
            description="Registered Email ID",
        ),
        password: SecretStr = Form(
            ...,
            description="User Password",
            min_length=8,
            max_length=20,
        ),
    ):
        self.email = email
        self.password = validate_password(password)


class RegistrationForm:
    def __init__(
        self,
        first_name: str = Form(
            ...,
            description="First Name of the User",
        ),
        last_name: str = Form(
            ...,
            description="Last Name of the User",
        ),
        email: EmailStr = Form(
            ...,
            description="Email ID for registration",
        ),
        password: SecretStr = Form(
            ...,
            description="User Password",
            min_length=8,
            max_length=20,
        ),
    ):
        self.first_name = validate_name(first_name, "first_name")
        self.last_name = validate_name(last_name, "last_name")
        self.email = email
        self.password = validate_password(password)
