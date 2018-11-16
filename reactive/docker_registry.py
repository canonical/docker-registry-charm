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


@when('apt.installed.docker.io')
@when_not('charm.docker-registry.configured')
def start():
    layer.status.maint('Configuring the registry.')

    layer.docker_registry.configure_registry()
    layer.docker_registry.start_registry()

    set_flag('charm.docker-registry.configured')
    report_status()


@when('charm.docker-registry.configured')
def report_status():
    '''Update status based on related charms/config.'''
    app_suffix = []
    charm_config = hookenv.config()
    name = charm_config.get('registry-name')
    netloc = layer.docker_registry.get_netloc()

    if layer.docker_registry.is_container(name, all=False):
        if is_flag_set('charm.docker-registry.tls-enabled'):
            app_suffix.append('https')
        else:
            app_suffix.append('http')
        if is_flag_set('website.available'):
            app_suffix.append('proxied')

        if app_suffix:
            status_suffix = ' ({})'.format(', '.join(app_suffix))
        else:
            status_suffix = ''
        layer.status.active('Listening on {}{}.'.format(netloc, status_suffix))
    else:
        layer.status.blocked('{} container is stopped.'.format(name))


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

    # Now that we reconfigured the registry, inform connected clients if
    # anything changed that they should know about.
    if (is_flag_set('charm.docker-registry.client-configured') and
            any((charm_config.changed('auth-basic-password'),
                 charm_config.changed('auth-basic-user'),
                 charm_config.changed('http-host')))):
        configure_client()

    report_status()


@when('charm.docker-registry.configured',
      'endpoint.docker-registry.joined')
@when_not('charm.docker-registry.client-configured')
def configure_client():
    '''Set all the registry config that clients may care about.'''
    registry = endpoint_from_flag('endpoint.docker-registry.joined')
    charm_config = hookenv.config()
    data = {}

    # auth config
    basic_password = charm_config.get('auth-basic-password')
    basic_user = charm_config.get('auth-basic-user')
    if basic_user and basic_password:
        # basic auth needs all or nothing
        data['basic_user'] = basic_user
        data['basic_password'] = basic_password
    else:
        data['basic_user'] = None
        data['basic_password'] = None

    # tls config
    if is_flag_set('charm.docker-registry.tls-enabled'):
        url_prefix = 'https'
        cert_provider = endpoint_from_flag('cert-provider.ca.available')
        if cert_provider:
            tls_ca = cert_provider.root_ca_cert
            data['tls_ca'] = tls_ca
    else:
        url_prefix = 'http'
        data['tls_ca'] = None

    # http config
    http_config = charm_config.get('http_config')
    netloc = layer.docker_registry.get_netloc()
    if http_config:
        # When set, trust that the user knows best
        data['registry_url'] = http_config
    else:
        data['registry_url'] = '{}://{}'.format(url_prefix, netloc)

    # send config
    hookenv.log('Sending {} config to client: {}.'.format(netloc, data))
    registry.set_registry_config(netloc, **data)
    set_flag('charm.docker-registry.client-configured')


@when('charm.docker-registry.configured',
      'charm.docker-registry.client-configured')
@when('endpoint.docker-registry.requests-pending')
def process_client_image_request():
    '''Handle a client request to host an image in the registry.'''
    hookenv.log('TODO: allow clients to request registry image')
    registry = endpoint_from_flag('endpoint.docker-registry.requests-pending')
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

            # If we have clients, let them know our tls data has changed
            if (is_flag_set('charm.docker-registry.client-configured')):
                configure_client()

            clear_flag('cert-provider.server.certs.changed')
            report_status()
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

    # If we have clients, let them know our tls data has changed
    if (is_flag_set('charm.docker-registry.client-configured')):
        configure_client()
    report_status()


@when('charm.docker-registry.configured')
@when('website.available')
def update_reverseproxy_config():
    website = endpoint_from_flag('website.available')
    port = hookenv.config().get('registry-port')
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
    website.configure(port=port)
    website.set_remote(all_services=services_yaml)

    # A proxy may change our netloc; if we have clients, tell them.
    netloc = layer.docker_registry.get_netloc()
    if data_changed('proxy_netloc', netloc):
        configure_client()


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
