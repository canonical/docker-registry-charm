from charms.unit_test import patch_fixture
from unittest import mock

from charmhelpers.core import host  # patched
from charms import layer

from reactive import docker_registry as handlers


start_registry = patch_fixture("charms.layer.docker_registry.start_registry")
stop_registry = patch_fixture("charms.layer.docker_registry.stop_registry")


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


@mock.patch("charms.layer.docker_registry._configure_local_client")
@mock.patch("charms.layer.docker_registry.host")
@mock.patch("charms.layer.docker_registry._write_tls_blobs_to_files")
@mock.patch("charms.layer.docker_registry.unitdata")
@mock.patch("charmhelpers.core.hookenv.config")
@mock.patch("os.makedirs", mock.Mock(return_value=0))
def test_configure_registry(config, mock_kv, mock_write, mock_host, mock_lc):
    config.return_value = {
        "log-level": "bananas",
        "storage-cache": "bananas",
    }
    expected = {
        "log": {"level": "bananas"},
        "storage": {"cache": {"blobdescriptor": "bananas"}},
    }

    with mock.patch("charms.layer.docker_registry.yaml") as mock_yaml:
        layer.docker_registry.configure_registry()
        args, _ = mock_yaml.safe_dump.call_args_list[0]
        assert expected["storage"].items() <= args[0]["storage"].items()
