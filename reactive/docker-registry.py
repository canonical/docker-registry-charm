import base64
import os
import yaml

from charmhelpers.core import (
    hookenv,
    host,
)
from charmhelpers.contrib.hahelpers import apache
from charms.reactive import (
    endpoint_from_flag,
    set_flag,
    clear_flag,
    when,
    when_any,
    when_not,
)
from charms import layer
from charms.leadership import leader_set, leader_get


CONFIG_FILE = '/etc/docker/registry/config.yml'
ROOT_CERTIFICATES_FILE = '/etc/docker/registry/token.pem'


@when_any('config.changed',
          'leadership.changed.http-secret')
def config_changed():
    clear_flag('charm.docker-registry.started')  # force update & restart


@when('apt.installed.docker.io')
@when_not('charm.docker-registry.started')
def start_registry():
    layer.status.maint('Configuring the registry')
    charm_config = hookenv.config()
    registry_config = {}

    # auth config
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
        registry_config["auth"] = auth

    # http config
    port = charm_config.get("port")
    http = {"addr": "0.0.0.0:{}".format(port)}
    if charm_config.get("http-host"):
        http["host"] = charm_config["http-host"]
    http_secret = leader_get("http-secret")
    if http_secret:
        http["secret"] = http_secret
    registry_config["http"] = http

    # log config
    registry_config["log"] = {
        "level": charm_config["log-level"],
        "formatter": "json",
        "fields": {
            "service": "registry",
        },
    }

    # storage config
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
        registry_config["storage"] = storage

    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    host.write_file(
        CONFIG_FILE,
        yaml.safe_dump(registry_config),
        perms=0o644,
    )

    # config determines external port, but the container always listens to 5000 internally
    from subprocess import check_call
    cmd = ['docker', 'run', '-d', '-p', '{}:5000'.format(port), '--restart', 'always',
           '--name', 'registry', 'registry:2']
    check_call(cmd)

    prev_port = charm_config.previous('port')
    if prev_port:
        hookenv.close_port(prev_port)
    hookenv.open_port(port)
    set_flag('charm.docker-registry.started')
    layer.status.active('Registry is active')


@when('website.changed')
def setup_website():
    # This is set on the relation for compatibility with haproxy.
    website = endpoint_from_flag('website.changed')
    port = hookenv.config().get('port')
    services_yaml = """
- service_name: %(service)s
  service_host: 0.0.0.0
  service_port: %(port)s
  service_options:
   - mode http
   - balance leastconn
   - option httpchk GET / HTTP/1.0
  servers:
   - [%(unit)s, %(addr)s, %(port)s, 'check port %(port)s']
""" % {
        'addr': hookenv.unit_private_ip(),
        'port': port,
        'service': hookenv.service_name(),
        'unit': hookenv.local_unit().replace('/', '-'),
    }
    website.configure(port, services=services_yaml)


@when('nrpe-external-master.available')
def setup_nagios():
    """Update the NRPE configuration for the given service."""
    hookenv.log("updating NRPE checks")
    nagios = endpoint_from_flag('nrpe-external-master.available')
    config = hookenv.config()
    check_args = {}
    if config.get('nagios_context'):
        check_args['context'] = config['nagios_context']
    if config.get('nagios_servicegroups'):
        check_args['servicegroups'] = config['nagios_servicegroups']
    nagios.add_check(['/usr/lib/nagios/plugins/check_http',
                      '-I', '127.0.0.1', '-p', str(config.get('port')),
                      '-e', " 200 OK", '-u', '/'],
                     name="check_http",
                     description="Verify docker-registry is responding",
                     **check_args)
    nagios.added()


@when('nrpe-external-master.removed')
def remove_nrpe_external():
    nagios = endpoint_from_flag('nrpe-external-master.removed')
    nagios.removed()


@when('leadership.is_leader')
@when_not('leadership.set.http-secret')
def generate_http_secret():
    leader_set({'http-secret': base64.b64encode(os.urandom(32)).decode('utf-8')})
