import base64
import os
import yaml

from charmhelpers.core import (
    hookenv,
    host,
)

from charms.reactive import set_flag, clear_flag, when, when_any, when_not
from charms.leadership import leader_set, leader_get


LISTEN_PORT = 5000
CONFIG_FILE = '/etc/docker/registry/config.yml'
ROOT_CERTIFICATES_FILE = '/etc/docker/registry/token.pem'


@when_any('config.changed',
          'leadership.changed.http-secret')
def config_changed():
    clear_flag('charm.docker-registry.started')  # force update & restart


@when('apt.installed.docker-registry')
@when_not('charm.docker-registry.started')
def start_service():
    charm_config = hookenv.config()
    # The config file is created by the deb so will always exist.
    with open(CONFIG_FILE) as f:
        registry_config = yaml.safe_load(f)

    auth = {}
    if charm_config.get("auth-token-realm"):
        # https://docs.docker.com/registry/configuration/#token
        auth["token"] = {
            "realm": charm_config.get("auth-token-realm", ""),
            "service": charm_config.get("auth-token-service", ""),
            "issuer": charm_config.get("auth-token-issuer", ""),
            "rootcertbundle": ROOT_CERTIFICATES_FILE,
        }
        host.write_file(
            ROOT_CERTIFICATES_FILE,
            charm_config.get("auth-token-root-certs", ""),
            perms=0o644,
        )

    if auth:
        registry_config["auth"] = auth
    elif 'auth' in registry_config:
        del registry_config["auth"]

    if charm_config.get("http-host"):
        # Note the "http" section will always be present from the deb
        # package configuration.
        registry_config["http"]["host"] = charm_config["http-host"]

    http_secret = leader_get("http-secret")
    if http_secret:
        registry_config["http"]["secret"] = http_secret

    registry_config["log"] = {
        "level": charm_config["log-level"],
        "formatter": "json",
        "fields": {
            "service": "registry",
        },
    }

    storage = {}
    if charm_config.get("storage-swift-authurl"):
        # https://docs.docker.com/registry/configuration/#storage
        storage["swift"] = {
            "authurl": charm_config.get("storage-swift-authurl", ""),
            "username": charm_config.get("storage-swift-username", ""),
            "password": charm_config.get("storage-swift-password", ""),
            "region": charm_config.get("storage-swift-region", ""),
            "container": charm_config.get("storage-swift-container", ""),
            "tenant": charm_config.get("storage-swift-tenant", ""),
        }
        storage["redirect"] = {"disable": True}

    if storage:
        registry_config["storage"] = storage

    host.write_file(
        CONFIG_FILE,
        yaml.safe_dump(registry_config),
        perms=0o644,
    )

    host.service_restart('docker-registry')
    hookenv.open_port(LISTEN_PORT)
    set_flag('charm.docker-registry.started')


@when('website.changed')
def setup_website(website):
    # This is set on the relation for compatibility with haproxy.
    services_yaml = """
- service_name: %(service)s
  service_host: 0.0.0.0
  service_port: 5000
  service_options:
   - mode http
   - balance leastconn
   - option httpchk GET / HTTP/1.0
  servers:
   - [%(unit)s, %(addr)s, %(port)s, 'check port %(port)s']
""" % {
        'addr': hookenv.unit_private_ip(),
        'port': LISTEN_PORT,
        'service': hookenv.service_name(),
        'unit': hookenv.local_unit().replace('/', '-'),
    }
    website.configure(LISTEN_PORT, services=services_yaml)


@when('nrpe-external-master.available')
def setup_nagios(nagios):
    """Update the NRPE configuration for the given service."""
    hookenv.log("updating NRPE checks")
    config = hookenv.config()
    check_args = {}
    if config.get('nagios_context'):
        check_args['context'] = config['nagios_context']
    if config.get('nagios_servicegroups'):
        check_args['servicegroups'] = config['nagios_servicegroups']
    nagios.add_check(['/usr/lib/nagios/plugins/check_http',
                      '-I', '127.0.0.1', '-p', str(LISTEN_PORT),
                      '-e', " 200 OK", '-u', '/'],
                     name="check_http",
                     description="Verify docker-registry is responding",
                     **check_args)
    nagios.added()


@when('nrpe-external-master.removed')
def remove_nrpe_external(nagios):
    nagios.removed()


@when('leadership.is_leader')
@when_not('leadership.set.http-secret')
def generate_http_secret():
    leader_set(base64.b64encode(os.urandom(32)).decode('utf-8'))
