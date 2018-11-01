import base64
import os

from charmhelpers.core import hookenv
from charms.reactive import (
    endpoint_from_flag,
    set_flag,
    clear_flag,
    is_flag_set,
    when,
    when_any,
    when_not,
)
from charms import layer
from charms.leadership import leader_set
from charms.reactive.helpers import data_changed


def report_active_status():
    '''Update status based on related charms/config.'''
    app_suffix = []
    if is_flag_set('charm.docker-registry.tls-enabled'):
        app_suffix.append('tls')
    else:
        app_suffix.append('insecure')
    if is_flag_set('website.available'):
        app_suffix.append('proxied')

    if app_suffix:
        status_suffix = ' ({})'.format(', '.join(app_suffix))
    else:
        status_suffix = ''
    layer.status.active('Ready{}.'.format(status_suffix))


@when('apt.installed.docker.io')
@when_not('charm.docker-registry.configured')
def start():
    layer.status.maint('Configuring the registry.')

    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()

    set_flag('charm.docker-registry.configured')
    report_active_status()


@when('charm.docker-registry.configured')
@when_any('config.changed',
          'leadership.changed.http-secret')
def config_changed():
    layer.status.maint('Reconfiguring the registry.')
    charm_config = hookenv.config()
    name = charm_config.get('registry-name')

    # If a provider gave us certs and http-host changed, make sure SANs are accurate
    if is_flag_set('cert-provider.certs.available') and charm_config.changed('http-host'):
        request_certificates()

    # If our name changed, make sure we stop the old one
    if charm_config.changed('registry-name') and charm_config.previous('registry-name'):
        name = charm_config.previous('registry-name')

    layer.docker_registry.stop_registry(name=name)
    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()

    report_active_status()


@when('charm.docker-registry.configured')
@when('endpoint.docker-registry.requests-pending')
def handle_requests():
    '''Set all the registry config that clients may care about.'''
    registry = endpoint_from_flag('endpoint.docker-registry.requests-pending')
    charm_config = hookenv.config()
    port = charm_config.get('registry-port')
    http_config = charm_config.get('http_config', '')

    # tls config
    url_prefix = 'http'
    tls_enabled = False
    tls_ca = None
    if is_flag_set('charm.docker-registry.tls-enabled'):
        url_prefix = 'https'
        tls_enabled = True
        cert_provider = endpoint_from_flag('cert-provider.ca.available')
        if cert_provider:
            tls_ca = cert_provider.root_ca_cert

    # http config
    if http_config and not http_config == "":
        # When set, this config is our source of truth for the registry url
        registry_url = http_config
    else:
        registry_url = '{}://{}:{}'.format(url_prefix, hookenv.unit_public_ip(), port)

    for request in registry.requests:
        hookenv.log('Sending {} and tls config to registry client.'.format(registry_url))
        request.set_registry_config(registry_url=registry_url,
                                    tls_enabled=tls_enabled,
                                    tls_ca=tls_ca)
    registry.mark_completed()


@when('cert-provider.available')
@when_not('cert-provider.certs.available')
def request_certificates():
    '''Request new certificate data.'''
    cert_provider = endpoint_from_flag('cert-provider.available')

    # Set the private ip of this unit as the Common Name for the cert.
    # NB: Any 'http-host' config will be added to the SANs list; we
    # want to ensure we always have a consistent CN regardless of config.
    cert_cn = hookenv.unit_private_ip()

    # Create a path safe name by removing path characters from the unit name.
    cert_name = hookenv.local_unit().replace('/', '_')

    # gather up all the alt names we want for our cert
    proxy_ep = endpoint_from_flag('proxy.available')
    sans = layer.docker_registry.get_tls_sans(proxy_ep.relation if proxy_ep else None)

    # if our alt names have changed, request a new cert
    if data_changed('tls_sans', sans):
        hookenv.log('Requesting new cert for CN: {} with SANs: {})'.format(cert_cn, sans))
        cert_provider.request_server_cert(cert_cn, sans, cert_name)
    else:
        hookenv.log('Not requesting new tls data; SANs did not change: {}'.format(sans))


@when('charm.docker-registry.configured')
@when('cert-provider.server.certs.changed')
def write_certs():
    '''Write cert data to our configured location.'''
    cert_provider = endpoint_from_flag('cert-provider.server.certs.changed')
    cert_cn = hookenv.unit_private_ip()
    ca = cert_provider.root_ca_cert
    cert = cert_provider.server_certs_map[cert_cn]

    # configure when we have everything we need
    if not (cert and ca and cert.cert and cert.key):
        layer.status.maint('Incomplete TLS data. Retrying.')
        clear_flag('charm.docker-registry.tls-enabled')
    else:
        layer.status.maint('Reconfiguring registry with TLS.')

        # Only configure/restart if cert data was written.
        if layer.docker_registry.write_tls(ca, cert.cert, cert.key):
            # NB: set the tls flag prior to calling configure
            set_flag('charm.docker-registry.tls-enabled')

            layer.docker_registry.stop_registry()
            layer.docker_registry.configure_registry()
            layer.docker_registry.start_registry()

            clear_flag('cert-provider.server.certs.changed')
            report_active_status()
        else:
            layer.status.maint('Could not write TLS data. Retrying.')
            clear_flag('charm.docker-registry.tls-enabled')


@when('charm.docker-registry.configured')
@when('charm.docker-registry.tls-enabled')
@when_not('cert-provider.available')
def remove_certs():
    '''Remove cert data from our configured paths when a tls provider is gone.'''
    # Remove cert data prior to reconfiguring/starting.
    layer.docker_registry.stop_registry()
    layer.docker_registry.remove_tls()

    # NB: remove the tls flag prior to calling configure
    clear_flag('charm.docker-registry.tls-enabled')
    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()
    report_active_status()


@when('charm.docker-registry.configured')
@when('website.available')
def update_reverseproxy_config():
    website = endpoint_from_flag('website.available')
    port = hookenv.config().get('registry-port')
    website.configure(port=port)

    services_yaml = """
- service_name: %(app)s
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
        'app': hookenv.application_name(),
        'unit': hookenv.local_unit().replace('/', '-'),
    }
    for rel in website.relations:
        rel.to_publish_raw.update({'all_services': services_yaml})


@when('charm.docker-registry.configured')
@when('nrpe-external-master.available')
def setup_nagios():
    '''Update the NRPE configuration for the given service.'''
    hookenv.log("updating NRPE checks")
    nagios = endpoint_from_flag('nrpe-external-master.available')
    charm_config = hookenv.config()

    check_args = {}
    if charm_config.get('nagios_context'):
        check_args['context'] = charm_config['nagios_context']
    if charm_config.get('nagios_servicegroups'):
        check_args['servicegroups'] = charm_config['nagios_servicegroups']
    nagios.add_check(['/usr/lib/nagios/plugins/check_http',
                      '-I', '127.0.0.1', '-p', str(charm_config.get('registry-port')),
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
