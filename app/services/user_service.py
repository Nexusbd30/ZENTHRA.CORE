from typing import Optional

from passlib.context import CryptContext
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user_schema import UserCreate, UserOutPaginated, UserRead, UserUpdate

# ==========================================================
# 🔐 CONFIGURACIÓN DE HASHING (bcrypt)
# ==========================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ==========================================================
# 🧠 SERVICIO DE USUARIOS — CAPA DE NEGOCIO
# ==========================================================
class UserService:
    """
    Capa de negocio encargada de la gestión de usuarios.
    Centraliza toda la lógica de negocio (no de persistencia):
      - Hashing y verificación de contraseñas
      - Creación y actualización segura
      - Paginación, búsqueda y eliminación
    """

    # ======================================================
    # 🔒 UTILIDADES DE SEGURIDAD
    # ======================================================
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Genera un hash seguro de la contraseña usando bcrypt."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifica si una contraseña en texto plano coincide con su hash."""
        return pwd_context.verify(plain_password, hashed_password)

    # ======================================================
    # 🟢 CREAR USUARIO
    # ======================================================
    @staticmethod
    def create_user(db: Session, user_data: UserCreate) -> User:
        """
        Crea un nuevo usuario:
          - Valida unicidad de email
          - Hashea la contraseña antes de guardar
        """
        hashed_password = UserService.get_password_hash(user_data.password)
        return UserRepository.create_user(db, user_data, hashed_password)

    # ======================================================
    # 🔍 OBTENER USUARIOS INDIVIDUALES
    # ======================================================
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Busca un usuario por su email."""
        return UserRepository.get_user_by_email(db, email)

    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Busca un usuario por su ID (UUID o entero)."""
        return UserRepository.get_user_by_id(db, user_id)

    # ======================================================
    # ✏️ ACTUALIZAR USUARIO
    # ======================================================
    @staticmethod
    def update_user(db: Session, user_id: str, updates: UserUpdate) -> Optional[User]:
        """
        Actualiza parcialmente los datos de un usuario existente.
        Campos posibles:
          - email
          - full_name
          - password (se rehashea automáticamente)
          - role
          - is_active
        """
        user = UserRepository.get_user_by_id(db, user_id)
        if not user:
            return None

        update_data = updates.dict(exclude_unset=True)

        # 🔐 Rehashear contraseña si se incluye en la actualización
        if "password" in update_data:
            new_password = update_data.pop("password")
            user.hashed_password = UserService.get_password_hash(new_password)

        # 🧩 Actualizar el resto de campos dinámicamente
        for key, value in update_data.items():
            setattr(user, key, value)

        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def set_user_active(db: Session, user_id: str, is_active: bool) -> Optional[User]:
        """Activa o desactiva un usuario existente."""
        user = UserRepository.get_user_by_id(db, user_id)
        if not user:
            return None

        user.is_active = is_active
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    # ======================================================
    # 🔑 RESETEAR CONTRASEÑA
    # ======================================================
    @staticmethod
    def reset_password(db: Session, email: str, new_password: str) -> Optional[User]:
        """
        Cambia la contraseña de un usuario existente.
        Hashea la nueva contraseña y actualiza el registro.
        """
        user = UserRepository.get_user_by_email(db, email)
        if not user:
            return None

        user.hashed_password = UserService.get_password_hash(new_password)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    # ======================================================
    # 🗑️ ELIMINAR USUARIO
    # ======================================================
    @staticmethod
    def delete_user(db: Session, user_id: str) -> bool:
        """Elimina un usuario de la base de datos por su ID."""
        user = UserRepository.get_user_by_id(db, user_id)
        if not user:
            return False

        UserRepository.delete_user(db, user)
        return True

    # ======================================================
    # 📄 LISTAR USUARIOS — PAGINACIÓN + FILTROS
    # ======================================================
    @staticmethod
    def get_users_paginated(
        db: Session,
        page: int = 1,
        limit: int = 10,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> UserOutPaginated:
        """
        Devuelve una lista paginada de usuarios con filtros opcionales:
          - role → Filtra por rol (admin/user)
          - is_active → Filtra por estado (activo/inactivo)
          - search → Busca coincidencias parciales por nombre o email
        """
        query = db.query(User)

        # Aplicar filtros dinámicos
        if role:
            query = query.filter(User.role == role)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        if search:
            like_search = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    User.email.ilike(like_search),
                    User.full_name.ilike(like_search),
                )
            )

        # Calcular total y paginación
        total = query.count()
        pages = (total + limit - 1) // limit
        users = query.offset((page - 1) * limit).limit(limit).all()
        user_items = [UserRead.model_validate(user) for user in users]

        return UserOutPaginated(
            items=user_items,
            total=total,
            page=page,
            pages=pages,
        )
