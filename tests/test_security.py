from datetime import datetime, timedelta

import pytest
from jose import jwt

from app.core.security import ALGORITHM, create_access_token


@pytest.mark.asyncio
async def test_expired_token(test_client):
    """Debe fallar si el token ya expiro."""
    token = create_access_token(
        {"sub": "expired@test.com"},
        expires_delta=timedelta(seconds=-1),
    )

    response = await test_client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "No se pudo validar las credenciales"


@pytest.mark.asyncio
async def test_invalid_signature_token(test_client):
    """Debe fallar si el token esta manipulado."""
    tampered_token = jwt.encode(
        {"sub": "fake@test.com", "exp": datetime.utcnow() + timedelta(minutes=15)},
        "WRONG_SECRET",
        algorithm=ALGORITHM,
    )

    response = await test_client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "No se pudo validar las credenciales"
