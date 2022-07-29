import base64
import os
import socket
import subprocess
import yaml

from pathlib import Path
from shutil import rmtree
from urllib.parse import urlparse

from charmhelpers.core import hookenv, host, unitdata
from charms.layer import docker
from charms.leadership import leader_get
from charms.reactive import endpoint_from_flag, is_flag_set
from charms.reactive.helpers import any_file_changed, data_changed


def configure_registry():
    '''Recreate the docker registry config.yml.'''
    charm_config = hookenv.config()
    registry_config = {'version': '0.1'}
    registry_config_file = '/etc/docker/registry/config.yml'

    # Some things need to be volume mounted in the container. Keep track of
    # those (recreate each time we configure). Regardless of the src location,
    # we explicitly mount config in the container under /etc/docker/registry.
    kv = unitdata.kv()
    kv.unset('docker_volumes')
    docker_volumes = {registry_config_file: '/etc/docker/registry/config.yml'}

    # auth (https://docs.docker.com/registry/configuration/#auth)
    auth = {}
    auth_basic = _get_auth_basic()
    if auth_basic:
        auth['htpasswd'] = auth_basic
        docker_volumes[auth_basic['path']] = '/etc/docker/registry/htpasswd'
    auth_token = _get_auth_token()
    if auth_token:
        auth['token'] = auth_token
        docker_volumes[auth_token['rootcertbundle']] = \
            '/etc/docker/registry/auth_token.pem'
    registry_config['auth'] = auth

    # http (https://docs.docker.com/registry/configuration/#http)
    port = charm_config.get('registry-port')
    http = {'addr': '0.0.0.0:{}'.format(port),
            'headers': {'X-Content-Type-Options': ['nosniff']},
            'relativeurls': True}
    if charm_config.get('http-host'):
        http['host'] = charm_config['http-host']
    http_secret = leader_get('http-secret')
    if http_secret:
        http['secret'] = http_secret

    # Only does anything if tls-*-blob set.
    _write_tls_blobs_to_files()

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

    # proxy (https://docs.docker.com/registry/configuration/#proxy)
    # Sets up registry as a pull-throuch cache
    if charm_config.get('cache-remoteurl'):
        registry_config['proxy'] = {
            'remoteurl': charm_config.get('cache-remoteurl', ''),
            'username': charm_config.get('cache-username', ''),
            'password': charm_config.get('cache-password', ''),
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

        # Openstack Domain settings
        # (https://docs.docker.com/registry/storage-drivers/swift/)
        val = charm_config.get('storage-swift-domain', '')
        if val != '':
            storage['swift'].update({'domain': val})

        storage['redirect'] = {'disable': True}
    else:
        # If we're not swift, we're local.
        container_registry_path = '/var/lib/registry'
        storage['filesystem'] = {'rootdirectory': container_registry_path}
        storage['cache'] = {'blobdescriptor': 'inmemory'}

        # Local storage is mounted from the host so images persist across
        # registry container restarts.
        host_registry_path = '/srv/registry'
        os.makedirs(host_registry_path, exist_ok=True)
        docker_volumes[host_registry_path] = container_registry_path
    if charm_config.get('storage-delete'):
        storage['delete'] = {'enabled': True}
    if charm_config.get('storage-read-only'):
        storage['maintenance'] = {'readonly': {'enabled': True}}
    registry_config['storage'] = storage

    os.makedirs(os.path.dirname(registry_config_file), exist_ok=True)
    host.write_file(
        registry_config_file,
        yaml.safe_dump(registry_config),
        perms=0o600,
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
    netloc = get_netloc()
    if is_flag_set('charm.docker-registry.tls-enabled'):
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
        # NB: these are the same certs used to serve the registry, but have
        # strict path requirements when used for docker client auth.
        client_tls_dst = '/etc/docker/certs.d/{}'.format(netloc)
        os.makedirs(client_tls_dst, exist_ok=True)
        tls_cert = charm_config.get('tls-cert-path', '')
        if os.path.isfile(tls_cert) and any_file_changed([tls_cert]):
            tls_cert_link = '{}/client.cert'.format(client_tls_dst)
            _remove_if_exists(tls_cert_link)
            os.symlink(tls_cert, tls_cert_link)
        tls_key = charm_config.get('tls-key-path', '')
        if os.path.isfile(tls_key) and any_file_changed([tls_key]):
            tls_key_link = '{}/client.key'.format(client_tls_dst)
            _remove_if_exists(tls_key_link)
            os.symlink(tls_key, tls_key_link)

        docker.delete_daemon_json('insecure-registries')
    else:
        docker.set_daemon_json('insecure-registries', [netloc])

    host.service_restart('docker')


def _get_auth_basic():
    '''Process our basic auth configuration.

    When required config is present (or changes), write an htpasswd file
    and construct a valid auth dict. When config is missing, remove any
    existing htpasswd file.

    :return: dict of htpasswd auth data, or None
    '''
    charm_config = hookenv.config()
    password = charm_config.get('auth-basic-password')
    user = charm_config.get('auth-basic-user')

    auth = {}
    htpasswd_file = '/etc/docker/registry/htpasswd'
    if user and password:
        auth = {
            'realm': hookenv.application_name(),
            'path': htpasswd_file,
        }
        # Only write a new htpasswd if something changed
        if data_changed('basic_auth', '{}:{}'.format(user, password)):
            if _write_htpasswd(htpasswd_file, user, password):
                msg = 'Wrote new {}; htpasswd auth is available'.format(
                    htpasswd_file)
            else:
                msg = 'Failed to write {}; htpasswd auth is unavailable'.format(
                    htpasswd_file)
                _remove_if_exists(htpasswd_file)
        else:
            msg = 'htpasswd auth is available'
    else:
        msg = 'Missing config: htpasswd auth is unavailable'
        _remove_if_exists(htpasswd_file)

    hookenv.log(msg, level=hookenv.INFO)
    return auth if os.path.isfile(htpasswd_file) else None


def _get_auth_token():
    '''Process our token auth configuration.

    When required config is present (or changes), write necessary pem bundle
    and construct a valid auth dict. When config is missing, remove any
    previously written bundle.

    :return: dict of token auth data, or None
    '''
    charm_config = hookenv.config()
    issuer = charm_config.get('auth-token-issuer')
    realm = charm_config.get('auth-token-realm')
    root_certs = charm_config.get('auth-token-root-certs')
    service = charm_config.get('auth-token-service')

    auth = {}
    cert_file = '/etc/docker/registry/auth_token.pem'
    if all((issuer, realm, root_certs, service)):
        auth = {
            'issuer': issuer,
            'realm': realm,
            'rootcertbundle': cert_file,
            'service': service,
        }
        # Only write a new cert bundle if root certs changed
        if data_changed('token_auth', root_certs):
            os.makedirs(os.path.dirname(cert_file), exist_ok=True)
            decoded = base64.b64decode(root_certs).decode('utf8')
            host.write_file(cert_file, content=decoded, perms=0o644)
            msg = 'Wrote new {}; token auth is available'.format(cert_file)
        else:
            msg = 'Token auth is available'
    else:
        msg = 'Missing config: token auth is unavailable'
        _remove_if_exists(cert_file)

    hookenv.log(msg, level=hookenv.INFO)
    return auth if os.path.isfile(cert_file) else None


def _remove_if_exists(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _write_htpasswd(path, user, password):
    '''Write an htpasswd file.

    :return: True if htpasswd succeeds; False otherwise
    '''
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cmd = ['htpasswd', '-Bbc', path, user, password]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('Error running htpasswd: {}'.format(e),
                    level=hookenv.ERROR)
        return False
    return True


def _write_tls_blobs_to_files():
    '''Write the user defined TLS blobs to files.

    :return: None
    '''
    charm_config = hookenv.config()

    blobs = [
        ('tls-cert-blob', 'tls-cert-path'),
        ('tls-ca-blob', 'tls-ca-path'),
        ('tls-key-blob', 'tls-key-path')
    ]

    for blob_key, path_key in blobs:
        blob = charm_config.get(blob_key)
        path = Path(charm_config.get(path_key))

        if blob and path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(blob))

        elif not path:
            hookenv.log('{} must be set.'.format(path_key))


def get_netloc():
    '''Get the network location (host:port) for this registry.

    If http-host config is present, return the netloc for that config.
    If related to a proxy, return the proxy netloc. Otherwise, return
    our private_adddress:port.
    '''
    charm_config = hookenv.config()
    netloc = None
    if charm_config.get('http-host'):
        netloc = urlparse(charm_config['http-host']).netloc
    else:
        # use the proxy address for our netloc (if available)
        proxy = endpoint_from_flag('website.available')
        if proxy:
            proxy_addrs = [
                hookenv.ingress_address(rid=u.rid, unit=u.unit)
                for u in hookenv.iter_units_for_relation_name(proxy.endpoint_name)
            ]
            # NB: get the first addr; presumably, the first will work just as
            # well as any other.
            try:
                netloc = proxy_addrs[0]
            except IndexError:
                # If we fail here, the proxy is probably departing; fall out
                # to the default netloc.
                pass
    if not netloc:
        netloc = '{}:{}'.format(hookenv.unit_private_ip(),
                                charm_config.get('registry-port', '5000'))
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


def is_container(name, all=True):
    '''Determine if a registry container is present on the system.

    Inform the caller if the named registry container exists. By default,
    this considers all containers. Restrict to running containers with the
    'all' parameter.

    :param: all: True looks for all containers; False just looks for running
    :return: True if container is present; False otherwise
    '''
    cmd = ['docker', 'container', 'list']
    if all:
        # show all containers
        cmd.append('--all')
    cmd.extend(['--filter', 'name={}'.format(name), '--format', '{{.Names}}'])
    try:
        containers = subprocess.check_output(cmd).decode('utf8')
    except subprocess.CalledProcessError as e:
        hookenv.log('Could not list existing containers: {}'.format(e),
                    level=hookenv.WARNING)
        containers = ''
    return name in containers


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

    if is_container(name):
        # start existing container
        cmd = ['docker', 'container', 'start', name]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            hookenv.log('Could not start existing container: {}'.format(name),
                        level=hookenv.ERROR)
            raise
    else:
        # NB: config determines the port, but the container always listens to 5000
        # https://docs.docker.com/registry/deploying/#customize-the-published-port
        cmd = ['docker', 'run', '-d', '-p', '{}:5000'.format(port),
               '--restart', 'unless-stopped']
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

    # only try to stop running containers
    if is_container(name, all=False):
        cmd = ['docker', 'container', 'stop', name]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            hookenv.log('Could not stop container: {}'.format(name),
                        level=hookenv.ERROR)
            raise

    # only try to remove existing containers
    if remove and is_container(name):
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
    '''Remove TLS cert data.'''
    charm_config = hookenv.config()
    tls_ca = charm_config.get('tls-ca-path', '')
    tls_cert = charm_config.get('tls-cert-path', '')
    tls_key = charm_config.get('tls-key-path', '')

    # unlink our registry tls files
    _remove_if_exists(tls_ca)
    _remove_if_exists(tls_cert)
    _remove_if_exists(tls_key)

    # unlink our local docker client tls data
    client_tls_dst = '/etc/docker/certs.d/{}'.format(get_netloc())
    if os.path.isdir(client_tls_dst):
        rmtree(client_tls_dst)

    # nullify our cached SANs; if a new tls relation is established, this
    # cache needs to be recreated.
    data_changed('tls_sans', None)
