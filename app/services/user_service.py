from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.security import hash_password, verify_password
from settings.config import get_settings
from uuid import UUID
import logging

# Retrieve and configure settings from your settings module
settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_username(cls, session: AsyncSession, username: str) -> Optional[User]:
        return await cls._fetch_user(session, username=username)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str]) -> Optional[User]:
        existing_user = await cls.get_by_username(session, user_data['username']) or \
                        await cls.get_by_email(session, user_data['email'])
        if existing_user:
            logger.error("User with given email or username already exists.")
            return None

        user_data['hashed_password'] = hash_password(user_data.pop('password'))
        new_user = User(**user_data)
        try:
            session.add(new_user)
            await session.commit()
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None
        except SQLAlchemyError as e:
            logger.error(f"Database error during user creation: {e}")
            await session.rollback()
            return None

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def login_user(cls, session: AsyncSession, username: str, password: str) -> Optional[User]:
        logger.debug(f"Attempting to log in user: {username}")
        user = await cls.get_by_username(session, username)
        if user:
            logger.debug(f"User found: {user.username}, verifying password...")
            if verify_password(password, user.hashed_password):
                logger.debug("Password verified successfully")
                # Update login time and reset attempts
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                return user
            else:
                logger.debug("Password verification failed")
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                    logger.debug("User account locked due to failed attempts")
                session.add(user)
                await session.commit()
        else:
            logger.debug("User not found")
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, username: str) -> bool:
        user = await cls.get_by_username(session, username)
        return user.is_locked if user else False

    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user:
            user.email_verified = True
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
