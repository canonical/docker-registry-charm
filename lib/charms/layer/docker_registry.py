import os
import socket
import yaml

from subprocess import check_call, check_output
from urllib.parse import urlparse

from charmhelpers.core import hookenv, host
from charms.leadership import leader_get

TLS_CERT_PATH = '/etc/docker/registry/server.crt'
TLS_KEY_PATH = '/etc/docker/registry/server.key'


def configure_registry():
    charm_config = hookenv.config()
    registry_config = {}
    registry_config_file = '/etc/docker/registry/config.yml'

    # auth config
    auth = {}
    if charm_config.get('auth-token-realm'):
        auth_token_bundle = '/etc/docker/registry/token.pem'
        # https://docs.docker.com/registry/configuration/#token
        auth['token'] = {
            'realm': charm_config.get('auth-token-realm', ''),
            'service': charm_config.get('auth-token-service', ''),
            'issuer': charm_config.get('auth-token-issuer', ''),
            'rootcertbundle': auth_token_bundle,
        }
        os.makedirs(os.path.dirname(auth_token_bundle), exist_ok=True)
        host.write_file(
            auth_token_bundle,
            charm_config.get('auth-token-root-certs', ''),
            perms=0o644,
        )
        registry_config['auth'] = auth

    # http config
    port = charm_config.get('port')
    http = {'addr': '0.0.0.0:{}'.format(port)}
    if charm_config.get('http-host'):
        http['host'] = charm_config['http-host']
    http_secret = leader_get('http-secret')
    if http_secret:
        http['secret'] = http_secret
    if os.path.isfile(TLS_CERT_PATH) and os.path.isfile(TLS_KEY_PATH):
        http['tls'] = {
            'certificate': TLS_CERT_PATH,
            'key': TLS_KEY_PATH,
        }
    registry_config['http'] = http

    # log config
    registry_config['log'] = {
        'level': charm_config['log-level'],
        'formatter': 'json',
        'fields': {
            'service': 'registry',
        },
    }

    # storage config
    storage = {}
    if charm_config.get('storage-swift-authurl'):
        # https://docs.docker.com/registry/configuration/#storage
        storage['swift'] = {
            'authurl': charm_config.get('storage-swift-authurl', ''),
            'username': charm_config.get('storage-swift-username', ''),
            'password': charm_config.get('storage-swift-password', ''),
            'region': charm_config.get('storage-swift-region', ''),
            'container': charm_config.get('storage-swift-container', ''),
            'tenant': charm_config.get('storage-swift-tenant', ''),
        }
        storage['redirect'] = {'disable': True}
        registry_config['storage'] = storage

    os.makedirs(os.path.dirname(registry_config_file), exist_ok=True)
    host.write_file(
        registry_config_file,
        yaml.safe_dump(registry_config),
        perms=0o644,
    )


def get_tls_sans(relation_name=None):
    '''Get all sans for our TLS certificate.

    Return all IP/DNS data that should included as alt names when we request
    a TLS cert. This includes our ingress address, local DNS name, any
    configured hostname, and the address of any related proxy.

    :return: sorted list of sans
    '''
    sans = [
        hookenv.unit_public_ip(),
        socket.gethostname(),
    ]
    http_config = hookenv.config('http-host')
    if http_config and not http_config == "":
        http_host = urlparse(http_config).hostname
        sans.append(http_host)

    if relation_name:
        proxy_sans = [hookenv.ingress_address(rid=u.rid, unit=u.unit)
                      for u in hookenv.iter_units_for_relation_name(relation_name)]
        sans.extend(proxy_sans)

    return sorted(sans)


def start_registry():
    '''Start a registry container.

    On intial invocation, create and run a new named registry container.
    Subsequent calls will start the existing named container.
    '''
    image = hookenv.config('registry-image')
    name = hookenv.config('registry-name')
    port = hookenv.config('port')

    cmd = ['docker', 'container', 'list', '--all',
           '--filter', 'name={}'.format(name), '--format', '{{.Names}}']
    if name in check_output(cmd).decode('utf8'):
        # start existing container
        cmd = ['docker', 'container', 'start', name]
        check_call(cmd)
    else:
        # config determines external port, but the container always listens to 5000 internally
        cmd = ['docker', 'run', '-d', '-p', '{}:5000'.format(port),
               '--restart', 'unless-stopped', '--name', name, image]
        check_call(cmd)

    hookenv.open_port(port)


def stop_registry(remove=False):
    '''Stop a registry:2 container.

    Stop and optionally remove the named registry container.
    :param remove: if true, remove the container after stopping
    '''
    name = hookenv.config('registry-name')
    cmd = ['docker', 'container', 'stop', name]
    check_call(cmd)
    if remove:
        cmd = ['docker', 'container', 'rm', '-v', name]
        check_call(cmd)

    port = hookenv.config('port')
    hookenv.close_port(port)


def write_tls(cert, key):
    '''Write TLS cert data to the filesystem.'''
    os.makedirs(os.path.dirname(TLS_CERT_PATH), exist_ok=True)
    host.write_file(TLS_CERT_PATH, cert, perms=0o644)
    host.write_file(TLS_KEY_PATH, key, perms=0o600)
