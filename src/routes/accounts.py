from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).filter(UserModel.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=UserGroupEnum.USER.value
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()

        return {"id": new_user.id, "email": new_user.email}

    except ValueError as validation_error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(validation_error)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def activate(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    email, token = data.email, data.token

    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.token == token,
        ActivationTokenModel.user_id == select(UserModel.id).where(UserModel.email == email).scalar_subquery()
    )
    result = await db.execute(stmt)
    activation_token = result.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    now_utc = datetime.now(timezone.utc)
    if activation_token.expires_at.tzinfo is None:
        activation_token.expires_at = activation_token.expires_at.replace(tzinfo=timezone.utc)

    if activation_token.expires_at < now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    stmt_user = select(UserModel).where(UserModel.email == email)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.commit()

    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.id == activation_token.id))
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        email = data.email
        result = await db.execute(select(UserModel).filter(UserModel.email == email))
        user = result.scalar_one_or_none()

        if user and user.is_active:
            existing_token = await db.execute(
                select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id)
            )
            existing_token = existing_token.scalar_one_or_none()

            if existing_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A password reset request is already pending."
                )

            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)
            await db.commit()

            return {"message": "If you are registered, you will receive an email with instructions."}

        return {"message": "If you are registered, you will receive an email with instructions."}

    except ValueError as validation_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(validation_error)
        )

    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = db_user.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        password_reset_token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
        password_reset_token_result = await db.execute(password_reset_token_stmt)
        password_reset_token = password_reset_token_result.scalars().first()
        if password_reset_token.token != data.token or cast(
                datetime, password_reset_token.expires_at
        ).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            await db.delete(password_reset_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        db_user.password = data.password
        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = db_user.scalar_one_or_none()
    if not db_user or not db_user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_manager.create_refresh_token(data={"user_id": db_user.id}),
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def acc_refresh(
        refresh_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    token_result = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_token.refresh_token
    ))
    if not token_result.scalar_one_or_none():
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_result = await db.execute(select(UserModel).where(UserModel.id == decoded_token.get("user_id")))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token(data={"user_id": decoded_token.get("user_id")})
    return {"access_token": access_token}
