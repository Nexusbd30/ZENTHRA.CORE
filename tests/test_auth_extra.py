import pytest

# ==========================================================
# 🧪 TESTS NEGATIVOS — AUTENTICACIÓN /auth/login
# ==========================================================
# Valida la respuesta del endpoint /auth/login frente a
# entradas inválidas, ausentes o con formato incorrecto.
#
# 🔧 Contexto:
# FastAPI utiliza OAuth2PasswordRequestForm, lo que significa que
# los campos `username` y `password` deben enviarse como
# form-data (application/x-www-form-urlencoded).
# ==========================================================


@pytest.mark.asyncio
async def test_login_missing_username(test_client):
    """
    ❌ Caso: falta el campo 'username'.
    Debe devolver un error 422 (Unprocessable Entity).
    """
    response = await test_client.post(
        "/auth/login",
        data={"password": "password123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 422, f"Esperado 422, obtenido {response.status_code}"
    data = response.json()

    # Aceptamos distintos tipos de error según FastAPI/Pydantic
    valid_error_types = {"missing", "value_error.missing", "model_attributes_type"}
    assert any(err.get("type") in valid_error_types for err in data.get("detail", [])), (
        f"Respuesta inesperada: {data}"
    )


@pytest.mark.asyncio
async def test_login_missing_password(test_client):
    """
    ❌ Caso: falta el campo 'password'.
    Debe devolver un error 422 (Unprocessable Entity).
    """
    response = await test_client.post(
        "/auth/login",
        data={"username": "user@test.com"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 422, f"Esperado 422, obtenido {response.status_code}"
    data = response.json()

    # Mismo criterio de validación flexible
    valid_error_types = {"missing", "value_error.missing", "model_attributes_type"}
    assert any(err.get("type") in valid_error_types for err in data.get("detail", [])), (
        f"No se detectó error de validación esperado: {data}"
    )


@pytest.mark.asyncio
async def test_login_empty_payload(test_client):
    """
    ❌ Caso: no se envía ningún dato.
    FastAPI debe devolver un error 422 por cuerpo vacío.
    """
    response = await test_client.post(
        "/auth/login",
        data={},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 422, f"Esperado 422, obtenido {response.status_code}"
    data = response.json()
    assert "detail" in data, f"Respuesta inesperada: {data}"


@pytest.mark.asyncio
async def test_login_invalid_json(test_client):
    """
    ❌ Caso: se envía JSON en lugar de form-data.
    Debe devolver error 422.
    """
    response = await test_client.post(
        "/auth/login",
        content='{"username": "user@test.com", "password": "1234"}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422, f"Esperado 422, obtenido {response.status_code}"
    data = response.json()
    assert "detail" in data, f"Respuesta inesperada: {data}"


@pytest.mark.asyncio
async def test_login_with_wrong_method(test_client):
    """
    ❌ Caso: se usa GET en lugar de POST.
    El endpoint /auth/login debe responder con 405.
    """
    response = await test_client.get("/auth/login")

    assert response.status_code == 405, f"Esperado 405, obtenido {response.status_code}"
    assert "Method Not Allowed" in response.text