from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @classmethod
    @field_validator("password")
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @classmethod
    @field_validator("password")
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
