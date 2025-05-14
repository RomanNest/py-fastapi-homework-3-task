from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from database.validators.accounts import validate_password_strength
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user_query = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    exists_user = user_query.scalar_one_or_none()
    if exists_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )

    try:
        validate_password_strength(user.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    hashed_psw = hash_password(user.password)

    user_group_query = await db.execute(
        select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    user_group = user_group_query.scalar_one_or_none()

    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User group 'USER' does not exist."
        )

    try:
        new_user = UserModel(
            email=user.email,
            _hashed_password=hashed_psw,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        activate_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activate_token)
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema.model_validate({
        "id": new_user.id,
        "email": user.email,
    })


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(
        user: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    query = await db.execute(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(joinedload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == user.token)
        .where(UserModel.email == user.email)
    )

    activation_token = query.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if cast(datetime, activation_token.expires_at).replace(
            tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user_activation = activation_token.user

    if user_activation.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user_activation.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
        request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    success_response = {
        "message": "If you are registered, "
                   "you will receive an email with instructions."
    }

    query = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    exists_user = query.scalar_one_or_none()

    if not exists_user or not exists_user.is_active:
        return success_response

    await db.execute(
        delete(PasswordResetTokenModel).
        where(PasswordResetTokenModel.user_id == exists_user.id)
    )
    reset_token = PasswordResetTokenModel(user_id=cast(int, exists_user.id))
    db.add(reset_token)
    await db.commit()
    return success_response


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
        request: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user_query = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    exists_user = user_query.scalar_one_or_none()

    if not exists_user or not exists_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_query = await db.execute(
        select(PasswordResetTokenModel).
        where(PasswordResetTokenModel.token == request.token).
        where(PasswordResetTokenModel.user_id == exists_user.id)
    )
    token = token_query.scalar_one_or_none()

    if not token:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == exists_user.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if (cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
            < datetime.now(timezone.utc)):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        validate_password_strength(request.password)
    except ValueError as e:
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    try:
        exists_user._hashed_password = hash_password(request.password)
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred while resetting the password.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
        request: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
        db: AsyncSession = Depends(get_db),
):
    query = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    exists_user = query.scalar_one_or_none()

    if not exists_user or not exists_user.verify_password(request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not exists_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": exists_user.id},
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": exists_user.id},
    )

    try:
        new_refresh_token = RefreshTokenModel.create(
            user_id=exists_user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(new_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred while processing the request.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return UserLoginResponseSchema.model_validate(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
        input_data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt_manager.decode_refresh_token(
            input_data.refresh_token,
        )
        user_id = payload.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            detail="Token has expired.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    token_query = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == input_data.refresh_token)
    )
    refresh_token = token_query.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_query = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    user = user_query.scalar_one_or_none()

    if not user:
        raise HTTPException(
            detail="User not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema.model_validate(
        {"access_token": access_token}
    )
