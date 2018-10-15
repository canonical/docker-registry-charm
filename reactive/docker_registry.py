import base64
import os

from charmhelpers.core import (
    hookenv,
    host,
)
from charms.reactive import (
    endpoint_from_flag,
    set_flag,
    clear_flag,
    when,
    when_any,
    when_not,
)
from charms import layer
from charms.leadership import leader_set
from charms.reactive.helpers import data_changed


@when_any('config.changed',
          'leadership.changed.http-secret')
@when('charm.docker-registry.started')
def config_changed():
    layer.status.maint('Reconfiguring the registry')

    layer.docker_registry.stop_registry()
    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()

    layer.status.active('Registry is active')


@when('apt.installed.docker.io')
@when_not('charm.docker-registry.started')
def start():
    layer.status.maint('Configuring the registry')

    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()

    set_flag('charm.docker-registry.started')
    layer.status.active('Registry is active')


@when('cert-provider.ca.changed')
def install_root_ca_cert():
    cert_provider = endpoint_from_flag('cert-provider.ca.available')
    host.install_ca_cert(cert_provider.root_ca_cert)
    clear_flag('cert-provider.ca.changed')


@when('cert-provider.available')
def request_certificates():
    cert_provider = endpoint_from_flag('cert-provider.available')

    # set the public ip of this unit as the Common Name for the cert
    cert_cn = hookenv.unit_public_ip()

    # Create a path safe name by removing path characters from the unit name.
    cert_name = hookenv.local_unit().replace('/', '_')

    # gather up all the alt names we want for our cert
    proxy_ep = endpoint_from_flag('proxy.available')
    sans = layer.docker_registry.get_tls_sans(proxy_ep.relation if proxy_ep else None)

    # if our alt names have changed, request a new cert
    if data_changed('tls_sans', sans):
        cert_provider.request_server_cert(cert_cn, sans, cert_name)


@when('cert-provider.certs.changed')
@when('charm.docker-registry.started')
def update_certs():
    cert_provider = endpoint_from_flag('cert-provider.available')
    server_cert = cert_provider.server_certs[0]  # only requested one
    layer.docker_registry.write_tls(server_cert.cert, server_cert.key)
    config_changed()
    clear_flag('cert-provider.certs.changed')


@when('proxy.available')
def setup_website():
    # This is set on the relation for compatibility with haproxy.
    website = endpoint_from_flag('proxy.available')
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
