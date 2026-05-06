
import uuid

import pytest

# ==========================================================
# 🔐 TEST DE AUTENTICACIÓN — ZENTHRA.CORE_SECURITY / NEXUSDB
# ==========================================================
# Este módulo prueba el flujo completo de autenticación:
# - Creación de usuario (POST /users/)
# - Login exitoso (POST /auth/login)
# - Login fallido con credenciales incorrectas
# ==========================================================

# Genera un email único por ejecución para evitar colisiones
TEST_EMAIL = f"login_{uuid.uuid4().hex[:6]}@test.com"
TEST_PASSWORD = "password123"
TEST_FULLNAME = "Test User"  # 👈 Campo requerido por el esquema UserCreate


@pytest.mark.asyncio
async def test_login_success(test_client):
    """
    ✅ Caso exitoso:
    - Crea un usuario nuevo en el sistema.
    - Realiza login con las credenciales correctas.
    - Debe devolver status 200 y un access_token válido.
    """

    # 1️⃣ Crear usuario de prueba con los campos requeridos
    create_resp = await test_client.post("/users/", json={
        "full_name": TEST_FULLNAME,  # 👈 Añadido para cumplir el modelo Pydantic
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    assert create_resp.status_code == 201, f"Error al crear usuario: {create_resp.text}"

    # 2️⃣ Intentar login con credenciales válidas
    login_resp = await test_client.post("/auth/login", json={
        "username": TEST_EMAIL,  # ⚠️ El campo sigue siendo 'username' por compatibilidad OAuth2
        "password": TEST_PASSWORD
    })

    # 3️⃣ Validar respuesta
    assert login_resp.status_code == 200, f"Login fallido: {login_resp.text}"
    data = login_resp.json()
    assert "access_token" in data, "No se devolvió el token de acceso"
    assert data["token_type"] == "bearer", "Tipo de token incorrecto"


@pytest.mark.asyncio
async def test_login_fail_invalid_credentials(test_client):
    """
    ❌ Caso fallido:
    - Intentar login con usuario inexistente o contraseña errónea.
    - Debe devolver 401 Unauthorized con mensaje 'Credenciales inválidas'.
    """

    # Intentar autenticarse con datos incorrectos
    response = await test_client.post("/auth/login", json={
        "username": "noexiste@test.com",
        "password": "wrongpassword"
    })

    # Validar resultado esperado
    assert response.status_code == 401, f"El servidor no devolvió 401: {response.text}"
    detail = response.json().get("detail")
    assert detail == "Credenciales inválidas", f"Mensaje inesperado: {detail}"