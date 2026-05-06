import uuid

import pytest


@pytest.mark.asyncio
async def test_threat_crud_admin_and_user_access(test_client, auth_token):
    user_email = f"th_user_{uuid.uuid4().hex[:6]}@test.com"
    user_password = "password123"

    create_user = await test_client.post(
        "/users/",
        json={"email": user_email, "password": user_password, "full_name": "Threat User"},
    )
    assert create_user.status_code == 201, create_user.text

    login_user = await test_client.post(
        "/auth/login",
        json={"username": user_email, "password": user_password},
    )
    assert login_user.status_code == 200, login_user.text
    user_token = login_user.json()["access_token"]

    payload = {
        "title": "CPU spike detected",
        "source": "manual",
        "description": "High CPU usage on node-1",
        "level": "high",
        "category": "performance",
        "score": 82,
        "target_service": "api",
    }

    create_threat = await test_client.post(
        "/threats/",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert create_threat.status_code == 201, create_threat.text
    threat = create_threat.json()
    threat_id = threat["id"]

    read_threat = await test_client.get(
        f"/threats/{threat_id}",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert read_threat.status_code == 200, read_threat.text
    assert read_threat.json()["id"] == threat_id

    update_threat = await test_client.put(
        f"/threats/{threat_id}",
        json={"title": "CPU spike resolved", "score": 40},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert update_threat.status_code == 200, update_threat.text
    assert update_threat.json()["title"] == "CPU spike resolved"

    delete_threat = await test_client.delete(
        f"/threats/{threat_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert delete_threat.status_code == 204, delete_threat.text

    get_deleted = await test_client.get(
        f"/threats/{threat_id}",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert get_deleted.status_code == 404, get_deleted.text


@pytest.mark.asyncio
async def test_threat_write_requires_admin(test_client):
    user_email = f"th_noadmin_{uuid.uuid4().hex[:6]}@test.com"
    user_password = "password123"

    create_user = await test_client.post(
        "/users/",
        json={"email": user_email, "password": user_password, "full_name": "No Admin"},
    )
    assert create_user.status_code == 201, create_user.text

    login_user = await test_client.post(
        "/auth/login",
        json={"username": user_email, "password": user_password},
    )
    assert login_user.status_code == 200, login_user.text
    user_token = login_user.json()["access_token"]

    create_threat = await test_client.post(
        "/threats/",
        json={"title": "Unauthorized threat", "source": "manual"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert create_threat.status_code == 403
