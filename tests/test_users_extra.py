import uuid

import pytest


@pytest.mark.asyncio
async def test_create_duplicate_user(test_client):
    email = f"dup_{uuid.uuid4().hex[:6]}@test.com"
    password = "password123"

    create = await test_client.post("/users/", json={"email": email, "password": password})
    assert create.status_code == 201

    dup = await test_client.post("/users/", json={"email": email, "password": password})
    assert dup.status_code == 400
    assert dup.json()["detail"] == "El email ya esta registrado" or dup.json()["detail"] == "El email ya está registrado"


@pytest.mark.asyncio
async def test_update_nonexistent_user(test_client):
    update = await test_client.put(
        "/users/99999",
        json={"email": "newemail@test.com", "is_active": True},
    )
    assert update.status_code in (401, 404)


@pytest.mark.asyncio
async def test_delete_nonexistent_user(test_client):
    delete = await test_client.delete("/users/99999")
    assert delete.status_code in (401, 404)


@pytest.mark.asyncio
async def test_reset_password_nonexistent_user(test_client):
    admin_email = f"missing_reset_admin_{uuid.uuid4().hex[:6]}@test.com"
    password = "password123"

    create = await test_client.post(
        "/users/",
        json={"email": admin_email, "password": password, "role": "admin"},
    )
    assert create.status_code == 201

    login = await test_client.post(
        "/auth/login",
        json={"username": admin_email, "password": password},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    reset = await test_client.post(
        "/users/reset-password",
        json={"email": "noexiste@test.com", "new_password": "whatever123"},
        headers=headers,
    )
    assert reset.status_code == 404
    assert reset.json()["detail"] == "Usuario no encontrado"


@pytest.mark.asyncio
async def test_reset_password_requires_authentication(test_client):
    reset = await test_client.post(
        "/users/reset-password",
        json={"email": "user@test.com", "new_password": "whatever123"},
    )

    assert reset.status_code == 401


@pytest.mark.asyncio
async def test_reset_password_rejects_other_non_admin_user(test_client):
    owner_email = f"owner_{uuid.uuid4().hex[:6]}@test.com"
    intruder_email = f"intruder_{uuid.uuid4().hex[:6]}@test.com"
    password = "password123"

    owner = await test_client.post("/users/", json={"email": owner_email, "password": password})
    intruder = await test_client.post("/users/", json={"email": intruder_email, "password": password})
    assert owner.status_code == 201
    assert intruder.status_code == 201

    login = await test_client.post(
        "/auth/login",
        json={"username": intruder_email, "password": password},
    )
    assert login.status_code == 200

    reset = await test_client.post(
        "/users/reset-password",
        json={"email": owner_email, "new_password": "changed123"},
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )

    assert reset.status_code == 403
    assert reset.json()["detail"] == "Solo puedes cambiar tu propia contraseña."


@pytest.mark.asyncio
async def test_update_user_invalid_email(test_client, auth_token):
    create = await test_client.post(
        "/users/",
        json={"email": "validupdate@test.com", "password": "password123"},
    )
    assert create.status_code == 201
    user_id = create.json()["id"]

    update = await test_client.put(
        f"/users/{user_id}",
        json={"email": "bademail"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert update.status_code == 422
