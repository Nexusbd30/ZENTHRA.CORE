from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.security import create_access_token, get_password_hash
from app.core.settings import settings
from app.core.tenant_context import current_tenant
from app.db.vector import SqlVectorStore
from app.models.runtime_state import RuntimeJob
from app.models.user import User
from app.models.verdict import Verdict
from app.runtime.orchestrator import RuntimeQueue
from tests.conftest import TestingSessionLocal


def identity(db, tenant, role='admin'):
    user = User(email=f'{uuid4().hex}@test.com', role=role, tenant_id=tenant,
                hashed_password=get_password_hash('strong-test-password'))
    db.add(user)
    db.commit()
    return {'Authorization': f'Bearer {create_access_token({"sub": user.email})}'}


@pytest.mark.asyncio
async def test_public_registration_cannot_select_privileges(test_client, monkeypatch):
    monkeypatch.setattr(settings, 'VAELQORIX_PUBLIC_REGISTRATION_ENABLED', True)
    email = f'{uuid4().hex}@test.com'
    created = await test_client.post('/users/', json={'email': email, 'password': 'strong-test-password',
                                                     'role': 'superadmin', 'is_active': False})
    assert created.status_code == 201
    assert created.json()['role'] == 'user'
    login = await test_client.post('/auth/login', json={'username': email, 'password': 'strong-test-password'})
    headers = {'Authorization': f'Bearer {login.json()["access_token"]}'}
    assert (await test_client.get('/users/', headers=headers)).status_code == 403
    assert (await test_client.get('/users/runtime-logs', headers=headers)).status_code == 403
    assert (await test_client.post('/users/admin', headers=headers,
            json={'email': f'{uuid4().hex}@test.com', 'password': 'strong-test-password', 'role': 'admin'})).status_code == 403


@pytest.mark.asyncio
async def test_tenant_reads_and_mutations_are_bound_to_account(test_client, db_session):
    first = identity(db_session, 'red')
    second = identity(db_session, 'blue')
    row = Verdict(target='host', action_type='observe', tenant_id='blue')
    db_session.add(row)
    db_session.commit()
    path = f'/api/v1/redqueen/verdicts/{row.verdict_id}'
    assert (await test_client.get(path, headers=first)).json()['status'] == 'not_found'
    assert (await test_client.get(path, headers=second)).json()['verdict_id'] == row.verdict_id
    assert (await test_client.get(path, headers={**first, 'X-Tenant-ID': 'blue'})).status_code == 403
    assert (await test_client.post(path + '/reject', headers=first)).json()['status'] == 'not_found'
    assert (await test_client.post('/api/v1/secops/tenant-policies', headers=first,
            json={'tenant_id': 'blue', 'name': 'forged'})).status_code == 403
    listing = await test_client.get('/users/', headers=first)
    assert len(listing.json()['items']) == 1
    assert (await test_client.get('/monitoring/logs', headers=first)).status_code == 403


@pytest.mark.asyncio
async def test_monitor_token_cannot_execute_control_operations(test_client, monkeypatch):
    monkeypatch.setattr(settings, 'VAELQORIX_MONITOR_TOKEN', 'read-only-monitor')
    for method, path in [('get', '/api/v1/ares/status'), ('post', '/api/v1/ares/kill-switch/on'),
                         ('post', '/monitoring/correlation/run')]:
        result = await getattr(test_client, method)(path, headers={'Authorization': 'Bearer read-only-monitor'})
        assert result.status_code == 403


@pytest.mark.asyncio
async def test_analyst_capabilities_are_reachable_but_admin_actions_denied(test_client, db_session):
    headers = identity(db_session, 'red', 'analyst')
    result = await test_client.get('/api/v1/secops/tenant-policies', headers=headers)
    assert result.status_code == 403  # security:admin, beyond analyst read access
    result = await test_client.get('/api/v1/identity/providers', headers=headers)
    assert result.status_code == 200, result.text


def test_scoped_session_rejects_cross_tenant_writes_and_relationships(db_session):
    row = User(email=f'{uuid4().hex}@test.com', hashed_password='hash', tenant_id='blue')
    db_session.add(row)
    db_session.commit()
    with TestingSessionLocal() as db:
        db.info['tenant_id'] = 'red'
        assert db.get(User, row.id) is None
        db.add(Verdict(target='host', action_type='observe', tenant_id='blue'))
        with pytest.raises(HTTPException):
            db.commit()
        db.rollback()


def test_sql_vectors_survive_new_instance_and_isolate_tenants(db_session):
    store = SqlVectorStore(TestingSessionLocal)
    token = current_tenant.set('red')
    try:
        store.upsert(collection='memory', record_id='one', text='ransomware lateral movement')
        restarted = SqlVectorStore(TestingSessionLocal)
        assert restarted.search(collection='memory', query='ransomware')[0]['id'] == 'one'
        assert restarted.status()['provider'] == 'sql_local'
        current_tenant.set('blue')
        assert restarted.search(collection='memory', query='ransomware') == []
        assert not restarted.delete_collection('memory')
    finally:
        current_tenant.reset(token)


def test_queue_survives_restarts_deduplicates_and_fences_workers(db_session):
    queue = RuntimeQueue('durability', session_factory=TestingSessionLocal)
    first = queue.enqueue({'task': 'one'}, idempotency_key='same')
    restarted = RuntimeQueue('durability', session_factory=TestingSessionLocal)
    assert restarted.enqueue({'task': 'one'}, idempotency_key='same')['job']['job_id'] == first['job']['job_id']
    with pytest.raises(HTTPException):
        restarted.enqueue({'task': 'different'}, idempotency_key='same')
    job = restarted.claim()
    assert job is not None
    assert queue.claim() is None
    assert not queue.finish(job['job_id'], 'wrong-lease')
    assert queue.finish(job['job_id'], job['lease_token'])
    assert not queue.finish(job['job_id'], job['lease_token'])


def test_queue_concurrent_duplicate_and_capacity(db_session):
    name = uuid4().hex
    queue = RuntimeQueue(name, max_size=1, session_factory=TestingSessionLocal)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: queue.enqueue({'task': 'one'}, idempotency_key='same'), range(4)))
    assert len({item['job']['job_id'] for item in results}) == 1
    assert queue.enqueue({'task': 'two'}, idempotency_key='other')['status'] == 'backpressure'
    assert queue.stats()['dead_letters'] == 0


def test_queue_failed_jobs_have_bounded_retries_and_retention(db_session):
    queue = RuntimeQueue('retry', session_factory=TestingSessionLocal, max_attempts=2)
    queue.enqueue({'task': 'one'})
    first = queue.claim()
    assert queue.finish(first['job_id'], first['lease_token'], error='failure')
    second = queue.claim()
    assert queue.finish(second['job_id'], second['lease_token'], error='failure')
    assert queue.claim() is None
    assert queue.stats()['dead_letters'] == 1
    with TestingSessionLocal() as db:
        row = db.scalar(select(RuntimeJob).where(RuntimeJob.job_id == first['job_id']))
        row.queued_at = datetime.utcnow() - timedelta(days=31)
        db.commit()
    assert queue.prune() == 1


@pytest.mark.asyncio
async def test_dns_provider_ingest_approve_execute_verify_and_rollback(test_client, db_session, monkeypatch):
    """Exercise the real webhook adapter against a stateful local controller."""
    state = {}
    calls = []

    class Controller(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            assert self.headers.get('Authorization') == 'Bearer integration-secret'
            command = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            payload = command['payload']
            calls.append(command['command'])
            key = (payload['tenant_id'], payload['target'])
            rule_id = 'provider-rule-001'
            if command['command'] == 'dns_firewall_block':
                state[key] = rule_id
                response = {'status': 'applied', 'request_id': 'request-apply', 'rule_id': rule_id}
            elif command['command'] == 'dns_firewall_rollback':
                state.pop(key, None)
                response = {'status': 'removed', 'request_id': 'request-remove', 'rule_id': rule_id}
            else:
                present = state.get(key) == payload['provider_rule_id']
                response = {'status': 'ok', 'request_id': 'request-verify', 'rule_id': rule_id,
                            'tenant_id': payload['tenant_id'], 'target': payload['target'], 'present': present}
            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Controller)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(settings, 'ACTION_EXECUTION_MODE', 'webhook')
    monkeypatch.setattr(settings, 'DNS_FIREWALL_CONTROL_URL', f'http://127.0.0.1:{server.server_port}/commands')
    monkeypatch.setattr(settings, 'ACTION_SHARED_TOKEN', 'integration-secret')
    monkeypatch.setattr(settings, 'ENV', 'test')
    monkeypatch.setattr(settings, 'REDQUEEN_HUMAN_APPROVAL_SCORE', 101)
    monkeypatch.setattr('app.redqueen.decision_engine.ai_provider.complete', lambda *args, **kwargs:
                        '{"action_type":"dns_firewall_block","confidence":0.95,"reasoning":"malware domain observed","factors":["malware_domain"]}')
    headers = identity(db_session, 'default')
    try:
        ingested = await test_client.post('/api/v1/ingestion/events', headers=headers, json={
            'source': 'network_sensor', 'title': 'Malware domain observed', 'category': 'network',
            'severity': 'medium', 'score': 60, 'target': 'malware.example',
            'fingerprint': uuid4().hex, 'event': {'signal': 'malware_domain'},
        })
        assert ingested.status_code == 200, ingested.text
        assert ingested.json()['status'] == 'created'
        decision = await test_client.post(
            f"/api/v1/redqueen/verdict/from-threat/{ingested.json()['threat_id']}", headers=headers,
            json={'execution_controls': {'dns_firewall_provider': 'webhook', 'change_ticket': 'CHG-1001'}},
        )
        assert decision.status_code == 200, decision.text
        verdict = decision.json()['verdict']
        assert verdict['action_type'] == 'dns_firewall_block'
        assert verdict['requires_human'] is True

        approved = await test_client.post('/api/v1/ares/approval-token', headers=headers,
            json={'verdict': verdict, 'approver': 'ignored-client-identity', 'reason': 'approved test block'})
        assert approved.status_code == 200, approved.text
        assert approved.json()['approver'] != 'ignored-client-identity'
        executed = await test_client.post('/api/v1/ares/execute', headers=headers,
            json={'verdict': verdict, 'human_approved': True, 'approval_evidence': approved.json()})
        assert executed.status_code == 200, executed.text
        assert executed.json()['execution']['status'] == 'success'
        assert state[('default', 'malware.example')] == 'provider-rule-001'
        executions = await test_client.get('/api/v1/ares/executions', headers=headers,
                                             params={'verdict_id': verdict['verdict_id']})
        assert executions.status_code == 200, executions.text
        execution_id = executions.json()['items'][0]['id']

        rollback = await test_client.post(f'/api/v1/ares/executions/{execution_id}/rollback', headers=headers,
            json={'reason': 'provider rollback verification'})
        assert rollback.status_code == 200, rollback.text
        assert rollback.json()['status'] == 'rolled_back'
        assert ('default', 'malware.example') not in state
        assert calls == ['dns_firewall_block', 'dns_firewall_verify',
                         'dns_firewall_rollback', 'dns_firewall_verify']
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
