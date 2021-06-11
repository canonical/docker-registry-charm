from charms.unit_test import patch_fixture

from charmhelpers.core import host  # patched
from charms import layer

from reactive import docker_registry as handlers


start_registry = patch_fixture('charms.layer.docker_registry.start_registry')
stop_registry = patch_fixture('charms.layer.docker_registry.stop_registry')


def test_series_upgrade(start_registry, stop_registry):
    assert start_registry.call_count == 0
    assert stop_registry.call_count == 0
    assert host.service_pause.call_count == 0
    assert host.service_resume.call_count == 0
    assert layer.status.blocked.call_count == 0
    handlers.pre_series_upgrade()
    assert start_registry.call_count == 0
    assert stop_registry.call_count == 1
    assert host.service_pause.call_count == 1
    assert host.service_resume.call_count == 0
    assert layer.status.blocked.call_count == 1
    handlers.post_series_upgrade()
    assert start_registry.call_count == 1
    assert stop_registry.call_count == 1
    assert host.service_pause.call_count == 1
    assert host.service_resume.call_count == 1
    assert layer.status.blocked.call_count == 1
