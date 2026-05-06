# ==========================================================
# 🧪 TESTS NEGATIVOS — VALIDACIÓN DE ERRORES (USERS / AUTH)
# ==========================================================
# Este módulo prueba el comportamiento del backend ante
# solicitudes incorrectas o acciones inválidas:
# - Acceso sin autenticación
# - Tokens inválidos
# - Emails duplicados
# - Operaciones sobre usuarios inexistentes
#
# Se prioriza validar códigos HTTP y estructuras de error
# más que coincidencias literales exactas en los mensajes.
# ==========================================================

import pytest

# ----------------------------------------------------------
# 🔒 TOKEN INVÁLIDO DE PRUEBA
# ----------------------------------------------------------
INVALID_TOKEN = "Bearer invalid.token.value"


# ----------------------------------------------------------
# 🧩 /users/me sin autenticación
# ----------------------------------------------------------
@pytest.mark.asyncio
async def test_me_user_without_token(test_client):
    """❌ Debe fallar si intentamos acceder a /users/me sin token."""
    response = await test_client.get("/users/me")

    assert response.status_code == 401, f"Esperado 401, recibido {response.status_code}"
    data = response.json()
    assert "detail" in data
    assert data["detail"] in ("Not authenticated", "Credenciales inválidas"), \
        f"Mensaje inesperado: {data}"


# ----------------------------------------------------------
# 🧩 /users/me con token inválido
# ----------------------------------------------------------
@pytest.mark.asyncio
async def test_me_user_with_invalid_token(test_client):
    """❌ Debe fallar si se usa un token JWT inválido."""
    response = await test_client.get(
        "/users/me",
        headers={"Authorization": INVALID_TOKEN}
    )

    assert response.status_code == 401, f"Esperado 401, recibido {response.status_code}"
    data = response.json()
    assert "detail" in data, "No se devolvió campo 'detail' en respuesta"
    assert "token" in str(data["detail"]).lower() or "credencial" in str(data["detail"]).lower(), \
        f"Mensaje inesperado: {data}"


# ----------------------------------------------------------
# 🧩 Crear usuario con email existente
# ----------------------------------------------------------
@pytest.mark.asyncio
async def test_create_user_with_existing_email(test_client, test_user):
    """❌ Debe fallar si intentamos registrar un email ya existente."""
    response = await test_client.post("/users/", json={
        "email": test_user["email"],
        "password": "otro_password123",
        "full_name": "Duplicado"
    })

    assert response.status_code == 400, f"Esperado 400, recibido {response.status_code}"
    detail = response.json().get("detail", "")
    assert "email" in detail.lower(), f"Mensaje inesperado: {detail}"
    assert "registrado" in detail.lower(), f"Mensaje inesperado: {detail}"


# ----------------------------------------------------------
# 🧩 Actualizar usuario inexistente
# ----------------------------------------------------------
@pytest.mark.asyncio
async def test_update_nonexistent_user(test_client, auth_token):
    """❌ Debe fallar si intentamos actualizar un usuario que no existe."""
    response = await test_client.put(
        "/users/9999",
        json={"email": "ghost@test.com"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 404, f"Esperado 404, recibido {response.status_code}"
    detail = response.json().get("detail", "")
    assert "usuario no encontrado" in detail.lower(), f"Mensaje inesperado: {detail}"


# ----------------------------------------------------------
# 🧩 Eliminar usuario inexistente
# ----------------------------------------------------------
@pytest.mark.asyncio
async def test_delete_nonexistent_user(test_client, auth_token):
    """❌ Debe fallar si intentamos eliminar un usuario que no existe."""
    response = await test_client.delete(
        "/users/9999",
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 404, f"Esperado 404, recibido {response.status_code}"
    detail = response.json().get("detail", "")
    assert "usuario no encontrado" in detail.lower(), f"Mensaje inesperado: {detail}"
