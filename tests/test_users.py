import pytest
from httpx import AsyncClient

TEST_EMAIL = "testuser@test.com"
TEST_PASSWORD = "testpassword123"
NEW_PASSWORD = "newpass123"
UPDATED_EMAIL = "updateduser@test.com"


@pytest.mark.asyncio
async def test_create_user(test_client: AsyncClient):
    response = await test_client.post(
        "/users/",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "Usuario de Prueba",
        },
    )

    assert response.status_code == 201, f"Error creando usuario: {response.text}"
    data = response.json()
    assert data["email"] == TEST_EMAIL
    assert "id" in data


@pytest.mark.asyncio
async def test_login_user(test_client: AsyncClient):
    response = await test_client.post(
        "/auth/login",
        json={"username": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert response.status_code == 200, f"Login fallido: {response.text}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    pytest.auth_token = data["access_token"]


@pytest.mark.asyncio
async def test_read_me_user(test_client: AsyncClient):
    headers = {"Authorization": f"Bearer {pytest.auth_token}"}

    response = await test_client.get("/users/me", headers=headers)
    assert response.status_code == 200, f"Error obteniendo perfil: {response.text}"

    data = response.json()
    assert data["email"] == TEST_EMAIL
    assert "id" in data


@pytest.mark.asyncio
async def test_list_users(test_client: AsyncClient, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}

    response = await test_client.get("/users/?page=1&limit=5", headers=headers)
    assert response.status_code == 200, f"Error al listar usuarios: {response.text}"

    data = response.json()
    assert isinstance(data.get("items"), list)
    assert "total" in data
    assert data["page"] == 1


@pytest.mark.asyncio
async def test_reset_password(test_client: AsyncClient):
    login = await test_client.post(
        "/auth/login",
        json={"username": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert login.status_code == 200, f"Error autenticando usuario para reset: {login.text}"
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = await test_client.post(
        "/users/reset-password",
        json={"email": TEST_EMAIL, "new_password": NEW_PASSWORD},
        headers=headers,
    )
    assert response.status_code == 200, f"Error al resetear contrasena: {response.text}"

    login = await test_client.post(
        "/auth/login",
        json={"username": TEST_EMAIL, "password": NEW_PASSWORD},
    )

    assert login.status_code == 200, f"Error al hacer login con nueva contrasena: {login.text}"
    assert "access_token" in login.json()


@pytest.mark.asyncio
async def test_update_user(test_client: AsyncClient, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}

    create = await test_client.post(
        "/users/",
        json={
            "email": "user_to_update@test.com",
            "password": "password123",
            "full_name": "Update Candidate",
        },
    )
    assert create.status_code == 201, f"Error creando usuario a actualizar: {create.text}"

    user_id = create.json().get("id")
    assert user_id, "No se obtuvo el ID del usuario"

    response = await test_client.put(
        f"/users/{user_id}",
        json={"email": UPDATED_EMAIL, "is_active": True},
        headers=headers,
    )

    assert response.status_code == 200, f"Error al actualizar usuario: {response.text}"
    data = response.json()
    assert data["email"] == UPDATED_EMAIL
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_delete_user(test_client: AsyncClient, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}

    create = await test_client.post(
        "/users/",
        json={
            "email": "user_to_delete@test.com",
            "password": "password123",
            "full_name": "Delete Candidate",
        },
    )
    assert create.status_code == 201, f"Error creando usuario a eliminar: {create.text}"

    user_id = create.json().get("id")
    assert user_id, "No se obtuvo ID del usuario"

    response = await test_client.delete(f"/users/{user_id}", headers=headers)
    assert response.status_code == 204, f"Error al eliminar usuario: {response.text}"


@pytest.mark.asyncio
async def test_toggle_user_active(test_client: AsyncClient, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}

    create = await test_client.post(
        "/users/",
        json={
            "email": "user_to_toggle@test.com",
            "password": "password123",
            "full_name": "Toggle Candidate",
            "is_active": True,
        },
    )
    assert create.status_code == 201, f"Error creando usuario a alternar: {create.text}"

    user_id = create.json().get("id")
    assert user_id, "No se obtuvo ID del usuario"

    response = await test_client.patch(
        f"/users/{user_id}/toggle-active",
        params={"is_active": False},
        headers=headers,
    )

    assert response.status_code == 200, f"Error al alternar usuario: {response.text}"
    assert response.json()["is_active"] is False
