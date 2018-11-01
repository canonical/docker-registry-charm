import os
import socket
import subprocess
import yaml

from urllib.parse import urlparse

from charmhelpers.core import hookenv, host, templating, unitdata
from charms.leadership import leader_get
from charms.reactive import is_flag_set
from charms.reactive.helpers import any_file_changed


def configure_registry():
    '''Recreate the docker registry config.yml.'''
    charm_config = hookenv.config()
    registry_config = {'version': '0.1'}
    registry_config_file = '/etc/docker/registry/config.yml'

    # Some files need to be volume mounted in the container. Keep track of
    # those (recreate each time we configure). Regardless of the src location,
    # we explictly mount them in the container under /etc/docker/registry.
    kv = unitdata.kv()
    kv.unset('docker_volumes')
    docker_volumes = {registry_config_file: '/etc/docker/registry/config.yml'}

    # auth (https://docs.docker.com/registry/configuration/#token)
    auth = {}
    if charm_config.get('auth-token-realm'):
        auth_token_bundle = '/etc/docker/registry/auth_token.pem'
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
        docker_volumes[auth_token_bundle] = '/etc/docker/registry/auth_token.pem'
        registry_config['auth'] = auth

    # http (https://docs.docker.com/registry/configuration/#http)
    port = charm_config.get('registry-port')
    http = {'addr': '0.0.0.0:{}'.format(port),
            'headers': {'X-Content-Type-Options': ['nosniff']}}
    if charm_config.get('http-host'):
        http['host'] = charm_config['http-host']
    http_secret = leader_get('http-secret')
    if http_secret:
        http['secret'] = http_secret
    tls_ca = charm_config.get('tls-ca-path', '')
    tls_cert = charm_config.get('tls-cert-path', '')
    tls_key = charm_config.get('tls-key-path', '')
    if os.path.isfile(tls_cert) and os.path.isfile(tls_key):
        http['tls'] = {
            'certificate': tls_cert,
            'key': tls_key,
        }
        docker_volumes[tls_cert] = '/etc/docker/registry/registry.crt'
        docker_volumes[tls_key] = '/etc/docker/registry/registry.key'

        if os.path.isfile(tls_ca):
            http['tls']['clientcas'] = [tls_ca]
            docker_volumes[tls_ca] = '/etc/docker/registry/ca.crt'
    registry_config['http'] = http

    # log (https://docs.docker.com/registry/configuration/#log)
    registry_config['log'] = {
        'level': charm_config['log-level'],
        'formatter': 'json',
        'fields': {
            'service': 'registry',
        }
    }

    # health (https://docs.docker.com/registry/configuration/#health)
    registry_config['health'] = {
        'storagedriver': {
            'enabled': True,
            'interval': '10s',
            'threshold': 3,
        }
    }

    # storage (https://docs.docker.com/registry/configuration/#storage)
    # we must have 1 (and only 1) storage driver
    storage = {}
    if charm_config.get('storage-swift-authurl'):
        storage['swift'] = {
            'authurl': charm_config.get('storage-swift-authurl', ''),
            'username': charm_config.get('storage-swift-username', ''),
            'password': charm_config.get('storage-swift-password', ''),
            'region': charm_config.get('storage-swift-region', ''),
            'container': charm_config.get('storage-swift-container', ''),
            'tenant': charm_config.get('storage-swift-tenant', ''),
        }
        storage['redirect'] = {'disable': True}
    else:
        storage['filesystem'] = {'rootdirectory': '/var/lib/registry'}
        storage['cache'] = {'blobdescriptor': 'inmemory'}
    registry_config['storage'] = storage

    os.makedirs(os.path.dirname(registry_config_file), exist_ok=True)
    host.write_file(
        registry_config_file,
        yaml.safe_dump(registry_config),
        perms=0o644,
    )

    # NB: all hooks will flush, but do an explicit one now in case we call
    # something that needs this data before our hook ends.
    kv.set('docker_volumes', docker_volumes)
    kv.flush(True)

    # Configure the system so our local 'docker' commands can interact
    # with the registry.
    _configure_local_client()


def _configure_local_client():
    '''Configure daemon.json and certs for the local docker client.'''
    charm_config = hookenv.config()

    # client config depends on whether the registry is secure or insecure
    netloc = _get_netloc()
    if is_flag_set('charm.docker-registry.tls-enabled'):
        insecure_registry = ''

        # if our ca changed, install it into the default sys location
        # (docker client > 1.13 will use this)
        tls_ca = charm_config.get('tls-ca-path', '')
        if os.path.isfile(tls_ca) and any_file_changed([tls_ca]):
            ca_content = None
            with open(tls_ca, 'rb') as f:
                ca_content = f.read()
            if ca_content:
                host.install_ca_cert(ca_content)

        # Put our certs where the docker client expects to find them
        # NB: these are the same certs used to serve the registry.
        tls_cert = charm_config.get('tls-cert-path', '')
        tls_key = charm_config.get('tls-key-path', '')
        if os.path.isfile(tls_cert) and os.path.isfile(tls_key):
            client_tls_dst = '/etc/docker/certs.d/{}'.format(netloc)
            os.makedirs(client_tls_dst, exist_ok=True)
            os.symlink(tls_cert, '{}/client.cert'.format(client_tls_dst))
            os.symlink(tls_key, '{}/client.key'.format(client_tls_dst))

    else:
        insecure_registry = '"{}"'.format(netloc)

    templating.render('daemon.json', '/etc/docker/daemon.json',
                      {'registries': insecure_registry})
    host.service_restart('docker')


def _get_netloc():
    '''Get the network location (host:port) for this registry.'''
    charm_config = hookenv.config()

    if charm_config.get('http-host'):
        netloc = urlparse(charm_config['http-host']).netloc
    else:
        netloc = '{}:{}'.format(hookenv.unit_private_ip(),
                                charm_config['registry-port'])

    return netloc


def get_tls_sans(relation_name=None):
    '''Get all sans for our TLS certificate.

    Return all IP/DNS data that should included as alt names when we request
    a TLS cert. This includes our public/private address, local DNS name, any
    configured hostname, and the address of any related proxy.

    :return: sorted list of sans
    '''
    charm_config = hookenv.config()
    sans = [
        hookenv.unit_private_ip(),
        hookenv.unit_public_ip(),
        socket.gethostname(),
    ]
    if charm_config.get('http-host'):
        http_host = urlparse(charm_config['http-host']).hostname
        sans.append(http_host)

    if relation_name:
        proxy_sans = [hookenv.ingress_address(rid=u.rid, unit=u.unit)
                      for u in hookenv.iter_units_for_relation_name(relation_name)]
        sans.extend(proxy_sans)

    return sorted(sans)


def start_registry(name=None, run_args=None):
    '''Start a registry container.

    If the named registry container doesn't exist, create and start a new
    container. Subsequent calls will start the existing named container. If a
    name is not specified, this method will use the configured 'registry-name'
    value.

    :param name: Name of the container to start
    :param run_args: list of additional args to pass to docker run
    '''
    charm_config = hookenv.config()
    image = charm_config.get('registry-image')
    port = charm_config.get('registry-port')
    if not name:
        name = charm_config.get('registry-name')

    cmd = ['docker', 'container', 'list', '--all',
           '--filter', 'name={}'.format(name), '--format', '{{.Names}}']
    try:
        containers = subprocess.check_output(cmd).decode('utf8')
    except subprocess.CalledProcessError as e:
        hookenv.log('Could not list existing containers: {}'.format(e),
                    level=hookenv.WARNING)
        containers = ''

    if name in containers:
        # start existing container
        cmd = ['docker', 'container', 'start', name]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            hookenv.log('Could not start existing container: {}'.format(name),
                        level=hookenv.ERROR)
            raise
    else:
        # NB: config determines the port, but the container always listens to 5000 internally
        cmd = ['docker', 'run', '-d', '-p', '{}:5000'.format(port), '--restart', 'unless-stopped']
        if run_args:
            cmd.extend(run_args)
        # Add our docker volume mounts
        volumes = unitdata.kv().get(key='docker_volumes', default={})
        for src, dest in volumes.items():
            cmd.extend(['-v', '{}:{}'.format(src, dest)])
        cmd.extend(['--name', name, image])
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            hookenv.log('Could not create new container: {}'.format(name),
                        level=hookenv.ERROR)
            raise

    hookenv.open_port(port)


def stop_registry(name=None, remove=True):
    '''Stop a registry container.

    Stop and optionally remove the named registry container. If a name is not
    specified, this method will stop the configured 'registry-name' container.

    :param name: Name of the container to stop
    :param remove: True removes the container after stopping
    '''
    charm_config = hookenv.config()
    port = charm_config.get('registry-port')
    if not name:
        name = charm_config.get('registry-name')

    cmd = ['docker', 'container', 'stop', name]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        hookenv.log('Could not stop container: {}'.format(name),
                    level=hookenv.ERROR)
        raise

    if remove:
        cmd = ['docker', 'container', 'rm', '--volumes', name]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            hookenv.log('Could not remove container: {}'.format(name),
                        level=hookenv.ERROR)
            raise

    hookenv.close_port(port)


def write_tls(ca, cert, key):
    '''Write TLS data to the filesystem.

    :return: True if ca, cert, and key were written; False otherwise
    '''
    charm_config = hookenv.config()
    tls_ca = charm_config.get('tls-ca-path')
    tls_cert = charm_config.get('tls-cert-path')
    tls_key = charm_config.get('tls-key-path')

    # NB: we may have to deal with operators that configure these options
    # individually; don't try to write anything until they're all present.
    if tls_ca and tls_cert and tls_key:
        os.makedirs(os.path.dirname(tls_ca), exist_ok=True)
        host.write_file(tls_ca, ca, perms=0o644)

        os.makedirs(os.path.dirname(tls_cert), exist_ok=True)
        host.write_file(tls_cert, cert, perms=0o644)

        os.makedirs(os.path.dirname(tls_key), exist_ok=True)
        host.write_file(tls_key, key, perms=0o600)
        return True
    else:
        return False


def remove_tls():
    '''Remove TLS cert data from the filesystem.'''
    charm_config = hookenv.config()
    tls_ca = charm_config.get('tls-ca-path', '')
    tls_cert = charm_config.get('tls-cert-path', '')
    tls_key = charm_config.get('tls-key-path', '')
    if os.path.isfile(tls_ca):
        os.remove(tls_ca)
    if os.path.isfile(tls_cert):
        os.remove(tls_cert)
    if os.path.isfile(tls_key):
        os.remove(tls_key)
