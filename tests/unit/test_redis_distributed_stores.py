from __future__ import annotations

from types import SimpleNamespace

from app.ares import kill_switch
from app.ares.kill_switch import RedisKillSwitchStore
from app.core import rate_limit, replay_guard
from app.core.rate_limit import RedisRateLimitStore
from app.core.replay_guard import RedisReplayGuardStore
from app.core.settings import settings


class FakePipeline:
    def __init__(self, client):
        self.client = client
        self.commands = []

    def zremrangebyscore(self, key, minimum, maximum):
        self.commands.append(("zremrangebyscore", key, minimum, maximum))
        return self

    def zcard(self, key):
        self.commands.append(("zcard", key))
        return self

    def zadd(self, key, mapping):
        self.commands.append(("zadd", key, mapping))
        return self

    def expire(self, key, ttl):
        self.commands.append(("expire", key, ttl))
        return self

    def execute(self):
        results = []
        for command in self.commands:
            name = command[0]
            if name == "zremrangebyscore":
                _, key, _minimum, maximum = command
                self.client.zsets[key] = {
                    member: score
                    for member, score in self.client.zsets.get(key, {}).items()
                    if score > maximum
                }
                results.append(1)
            elif name == "zcard":
                _, key = command
                results.append(len(self.client.zsets.get(key, {})))
            elif name == "zadd":
                _, key, mapping = command
                self.client.zsets.setdefault(key, {}).update(mapping)
                results.append(1)
            elif name == "expire":
                results.append(True)
        return results


class FakeRedisClient:
    def __init__(self):
        self.zsets = {}
        self.values = {}

    def pipeline(self):
        return FakePipeline(self)

    def zrange(self, key, start, stop, withscores=False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda item: item[1])
        selected = items[start : stop + 1]
        return selected if withscores else [item[0] for item in selected]

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = {"value": value, "ex": ex}
        return True

    def get(self, key):
        item = self.values.get(key)
        if not item:
            return None
        return item["value"]

    def scan_iter(self, match):
        prefix = match.rstrip("*")
        keys = [*self.zsets.keys(), *self.values.keys()]
        return [key for key in keys if key.startswith(prefix)]

    def delete(self, key):
        self.zsets.pop(key, None)
        self.values.pop(key, None)


def test_redis_rate_limit_store_enforces_window(monkeypatch):
    fake_client = FakeRedisClient()
    monkeypatch.setattr(
        rate_limit,
        "redis",
        SimpleNamespace(Redis=SimpleNamespace(from_url=lambda *args, **kwargs: fake_client)),
    )
    store = RedisRateLimitStore(url="redis://test", key_prefix="test")

    first = store.check(key="tenant:ip:entra", limit=1, window_seconds=60)
    second = store.check(key="tenant:ip:entra", limit=1, window_seconds=60)

    assert first.allowed is True
    assert first.remaining == 0
    assert second.allowed is False
    assert second.retry_after_seconds >= 1
    assert "test:rate_limit:tenant:ip:entra" in fake_client.zsets


def test_redis_replay_guard_store_accepts_only_first_key(monkeypatch):
    fake_client = FakeRedisClient()
    monkeypatch.setattr(
        replay_guard,
        "redis",
        SimpleNamespace(Redis=SimpleNamespace(from_url=lambda *args, **kwargs: fake_client)),
    )
    store = RedisReplayGuardStore(url="redis://test", key_prefix="test")

    first = store.check(key="payload-hash", ttl_seconds=300)
    second = store.check(key="payload-hash", ttl_seconds=300)

    assert first.accepted is True
    assert second.accepted is False
    assert fake_client.values["test:replay:payload-hash"]["ex"] == 300


def test_redis_kill_switch_store_shares_state(monkeypatch):
    fake_client = FakeRedisClient()
    monkeypatch.setattr(
        kill_switch,
        "redis",
        SimpleNamespace(Redis=SimpleNamespace(from_url=lambda *args, **kwargs: fake_client)),
    )
    first = RedisKillSwitchStore(url="redis://test", key_prefix="test", key="ares:kill_switch")
    second = RedisKillSwitchStore(url="redis://test", key_prefix="test", key="ares:kill_switch")

    first.write(
        {
            "enabled": False,
            "reason": "provider outage",
            "actor": "soc-admin",
            "updated_at": "2026-08-11T00:00:00+00:00",
        }
    )

    assert second.read()["enabled"] is False
    assert second.read()["reason"] == "provider outage"
    assert "test:ares:kill_switch" in fake_client.values


def test_kill_switch_state_fails_closed_when_redis_unavailable(monkeypatch):
    class BrokenRedis:
        @staticmethod
        def from_url(*args, **kwargs):
            raise RuntimeError("redis unavailable")

    monkeypatch.setattr(settings, "ARES_KILL_SWITCH_BACKEND", "redis")
    monkeypatch.setattr(kill_switch, "redis", SimpleNamespace(Redis=BrokenRedis))
    kill_switch.reset_kill_switch_store()

    state = kill_switch.kill_switch_state()

    assert state["ares_enabled"] is False
    assert state["active"] is True
    assert state["fail_closed"] is True
    assert state["backend"] == "redis"
