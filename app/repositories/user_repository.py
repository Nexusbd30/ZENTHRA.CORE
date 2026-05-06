from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user_schema import UserCreate, UserUpdate


class UserRepository:
    """
    Repositorio encargado de gestionar todas las operaciones CRUD
    sobre la entidad User utilizando SQLAlchemy ORM.
    """

    # ==========================================================
    # 🟢 CREAR USUARIO
    # ==========================================================
    @staticmethod
    def create_user(db: Session, user: UserCreate, hashed_password: str) -> User:
        """
        Crea un nuevo usuario en la base de datos.
        - Encripta la contraseña previamente.
        - Define rol y estado activo por defecto.
        """
        db_user = User(
            email=user.email,
            full_name=user.full_name,
            hashed_password=hashed_password,
            role=user.role or "user",
            is_active=user.is_active if user.is_active is not None else True,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    # ==========================================================
    # 🔍 LECTURAS (READ)
    # ==========================================================
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Obtiene un usuario por su email único."""
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Obtiene un usuario por su ID (UUID o int, según modelo)."""
        return db.query(User).filter(User.id == user_id).first()

    # ==========================================================
    # 🧩 ACTUALIZAR USUARIO
    # ==========================================================
    @staticmethod
    def update_user(db: Session, user: User, updates: UserUpdate) -> User:
        """
        Actualiza parcialmente los campos del usuario.
        Solo modifica los campos enviados en el payload.
        """
        update_data = updates.dict(exclude_unset=True)
        for key, value in update_data.items():
            # Excluye valores vacíos (None o cadenas vacías)
            if value is not None and value != "":
                setattr(user, key, value)

        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    # ==========================================================
    # 🗑️ ELIMINAR USUARIO
    # ==========================================================
    @staticmethod
    def delete_user(db: Session, user: User) -> None:
        """Elimina físicamente un usuario de la base de datos."""
        db.delete(user)
        db.commit()

    # ==========================================================
    # 📄 PAGINACIÓN Y FILTROS (para dashboards o APIs)
    # ==========================================================
    @staticmethod
    def get_users_filtered(
        db: Session,
        page: int = 1,
        limit: int = 10,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> tuple[List[User], int]:
        """
        Devuelve una lista paginada de usuarios con filtros y búsqueda.
        - Filtra por rol o estado activo.
        - Busca por coincidencias parciales de nombre o email.
        - Retorna (lista_de_usuarios, total_de_registros).
        """
        query = db.query(User)

        if role:
            query = query.filter(User.role == role)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        if search:
            like_term = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    User.full_name.ilike(like_term),
                    User.email.ilike(like_term),
                )
            )

        total = query.count()
        users = query.offset((page - 1) * limit).limit(limit).all()

        return users, total