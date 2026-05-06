# tests/test_user_service.py
import pytest


@pytest.mark.asyncio
async def test_create_and_read_user(test_client, auth_token):
    """Debe crear un usuario y luego obtenerlo por ID"""
    email = "serviceuser@test.com"
    password = "servicepass123"

    # Crear usuario
    create = await test_client.post("/users/", json={
        "email": email, "password": password
    })
    assert create.status_code == 201
    user_id = create.json()["id"]

    # Obtener usuario por ID (nuevo endpoint en users.py)
    get_user = await test_client.get(
        f"/users/{user_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert get_user.status_code == 200
    data = get_user.json()
    assert data["id"] == user_id
    assert data["email"] == email


@pytest.mark.asyncio
async def test_update_user_email(test_client, auth_token, test_user):
    """Debe actualizar el email de un usuario existente"""
    new_email = "updated_service@test.com"

    update = await test_client.put(
        f"/users/{test_user['id']}",
        json={"email": new_email},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert update.status_code == 200
    data = update.json()
    assert data["email"] == new_email


@pytest.mark.asyncio
async def test_update_user_password_only(test_client, auth_token, test_user):
    """Debe actualizar solo la contraseña y permitir login con la nueva"""
    new_password = "newpass456"

    # Cambiar solo la contraseña
    update = await test_client.put(
        f"/users/{test_user['id']}",
        json={"password": new_password},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert update.status_code == 200

    # Login con nueva contraseña
    login = await test_client.post("/auth/login", json={
        "username": test_user["email"],
        "password": new_password
    })
    assert login.status_code == 200
    assert "access_token" in login.json()


@pytest.mark.asyncio
async def test_delete_user_and_verify(test_client, auth_token, test_user):
    """Debe eliminar un usuario y luego devolver 404 al buscarlo"""
    delete = await test_client.delete(
        f"/users/{test_user['id']}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert delete.status_code == 204

    # Intentar obtener el usuario eliminado
    get_user = await test_client.get(
        f"/users/{test_user['id']}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert get_user.status_code == 404
