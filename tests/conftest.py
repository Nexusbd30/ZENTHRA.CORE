import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import get_db
from app.main import app
from app.models.base import Base
from app.models.threat_model import ThreatModel  # noqa: F401
from app.models.user import User  # noqa: F401

TEST_DB_URL = "sqlite:///./test.db"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
TestingSessionLocal = sessionmaker(
    bind=test_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest_asyncio.fixture(scope="session")
async def test_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def test_user(test_client):
    email = f"user_{uuid.uuid4().hex[:8]}@test.com"
    password = "password123"

    response = await test_client.post(
        "/users/",
        json={
            "email": email,
            "password": password,
            "full_name": "Usuario de Prueba",
        },
    )
    assert response.status_code == 201, f"Error creando test_user: {response.text}"
    data = response.json()
    return {"id": data.get("id"), "email": email, "password": password}


@pytest_asyncio.fixture(scope="session")
async def auth_token(test_client):
    test_email = "auth_fixture_admin@test.com"
    test_password = "secure123"

    create_resp = await test_client.post(
        "/users/",
        json={
            "email": test_email,
            "password": test_password,
            "full_name": "Token Tester",
            "role": "admin",
        },
    )
    assert create_resp.status_code in (201, 400), (
        f"Error creando usuario auth_token: {create_resp.text}"
    )

    login_resp = await test_client.post(
        "/auth/login",
        json={"username": test_email, "password": test_password},
    )
    assert login_resp.status_code == 200, (
        f"No se pudo autenticar usuario auth_token: {login_resp.text}"
    )
    token = login_resp.json().get("access_token")
    assert token, "No se devolvio access_token"
    return token
