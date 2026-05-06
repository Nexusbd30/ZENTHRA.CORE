# tests/test_health.py
import pytest


@pytest.mark.asyncio
async def test_health_check(test_client):
    """
    ✅ Test del endpoint /health
    - Debe devolver status 200
    - Contener 'status': 'ok'
    - Incluir el mensaje esperado
    - Incluir la variable de entorno activa
    """
    response = await test_client.get("/health")

    # 🔍 Validaciones
    assert response.status_code == 200, "El endpoint /health no devolvió 200"
    data = response.json()

    assert data["status"] == "ok", "El campo 'status' no es 'ok'"
    assert "El servidor está corriendo" in data["message"], "El mensaje no contiene el texto esperado"

    # ⚙️ validar entorno sin hardcodear
    assert data["env"] in ("dev", "prod", "test"), f"Entorno inesperado: {data['env']}"