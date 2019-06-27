# Introduction

This charm provides a registry for storage and distribution of docker images.
See https://docs.docker.com/registry/ for details.

## Deployment

The registry is deployed as a stand alone application and supports integration
with clients that implement the [docker-registry][interface] interface.

[interface]: https://github.com/juju-solutions/interface-docker-registry

### Standalone Registry

For testing purposes, a simple, insecure registry can be deployed with:

```bash
juju deploy ~containers/docker-registry
```

### Secure Registry with TLS

This charm supports TLS via the `tls-certificates` relation. This can
be enabled by deploying and relating to a TLS provider, such as `easyrsa`:

```bash
juju deploy ~containers/docker-registry
juju deploy ~containers/easyrsa

juju add-relation easyrsa docker-registry
```

This charm also supports configuration-based TLS, which does not require a
relation to a TLS provider. Instead, transfer required files and configure
this charm as follows:

```bash
juju scp /my/local/ca.pem docker-registry/0:/home/ubuntu/ca.pem
juju scp /my/local/cert.crt docker-registry/0:/home/ubuntu/cert.crt
juju scp /my/local/cert.key docker-registry/0:/home/ubuntu/cert.key

juju config docker-registry \
  tls-ca-path=/home/ubuntu/ca.pem \
  tls-cert-path=/home/ubuntu/cert.crt \
  tls-key-path=/home/ubuntu/cert.key
```

Finally, custom TLS data may be provided as base64-encoded config options to
the charm. The configured `tls-*-blob` data will be written to corresponding
configured `tls-*-path` files:

```bash
juju config docker-registry \
  tls-ca-blob=$(base64 /path/to/ca) \
  tls-cert-blob=$(base64 /path/to/cert) \
  tls-key-blob=$(base64 /path/to/key)
```

### Proxied Registry

This charm supports `http` proxy relation that allows operators to
control how the registry is exposed on the network. This is achieved by
relating to a proxy provider, such as `haproxy`.

#### TLS/SSL
TLS is supported between `haproxy` and `docker-registry` although some manual configuration is required.

You will be required to create the directory structure suppled to the `docker-registry` charm config `tls-ca-path` and copy your proxy's PEM, along with your CAs certificate to that directory.

By default charm config is set to `/etc/docker/registry` to check you can run: `juju config --model <YOURMODEL> docker-registry`.

The steps to configure are set out below:
```
1. juju ssh haproxy/$UNIT_NUM
2. mkdir -p <$TLS_CA_PATH>
3. (Might not be required): chown -R ubuntu:ubuntu <$TLS_CA_PATH>
4. ctrl+d
5a. juju config haproxy ssl_key=$BASE64_PROXY_KEY ssl_cert=$BASE64_PROXY_CERT
5b. juju scp <CA.crt> haproxy/$UNIT_NUM:<$TLS_CA_PATH>/
6. juju resolve haproxy/$UNIT_NUM
```

haproxy should now come back up.
> Please note depending on your certificates you may be required to add the proxy to your insecure registries in [`daemon.json`](https://docs.docker.com/registry/insecure/)

```bash
juju deploy ~containers/docker-registry
juju deploy haproxy

juju add-relation haproxy docker-registry
```

When multiple `docker-registry` units are deployed, the proxy will be
configured with one unit chosen as the primary proxied service with remaining
units configured as backups. This provides a highly available deployment that
will fail over to a backup if the primary service becomes unavailable.

>Note: HA deployments require the proxy to be in `active-passive` peering
mode, which is the default for `haproxy`.

### Nagios Monitoring

This charm supports monitoring with nagios:

```bash
juju deploy ~containers/docker-registry
juju deploy nrpe --series bionic

juju relate docker-registry nrpe
```

### Kubernetes Integration

See the [Private Docker Registry][k8s-docs] documentation for details on
integrating this charm with Kubernetes.

[k8s-docs]: https://www.ubuntu.com/kubernetes/docs/docker-registry

## Actions

### Adding Images

To make an image available in the deployed registry, it must be tagged and
pushed. This charm provides the `push` action to do this:

```bash
juju run-action --wait docker-registry/0 push \
  image=<image> pull=<True|False> tag=<optional-tag-name>
```

This action will always tag and push a local image to the registry. By
specifying `pull=True` (the default), the action will first pull the
given `image` and subsequently tag/push it.

The default image tag is 'net_loc/name:version', where 'net_loc' is the
`http-host` config option or http[s]://[private-ip]:[port] if config is not
set. The image tag can be overriden by specifying the `tag` action parameter.

### Listing Images

List images known to the registry with the `images` action:

```bash
juju run-action --wait docker-registry/0 images \
  options=<extra-args> repository=<repository[:tag]>
```

This runs `docker images` on the registry machine. The optional `options` and
`repository` parameters are passed through to the underlying command. For
example, show non-truncated output with numeric image IDs:

```bash
juju run-action --wait docker-registry/0 images \
  options="--no-trunc --quiet"
```

### Removing Images

Remove images from the registry with the `rmi` action:

```bash
juju run-action --wait docker-registry/0 rmi \
  options=<extra-args> image=<image [image...]>
```

This runs `docker rmi` on the registry machine. The image name (or space
separated names) must be specified using the `image` parameter. The optional
`options` parameter is passed through to the underlying command. For
example, remove the ubuntu:18.04 image without deleting untagged parents:

```bash
juju run-action --wait docker-registry/0 rmi \
  options="--no-prune" image="ubuntu:18.04"
```

### Starting/Stopping

The registry is configured to start automatically with the dockerd system
service. It can also be started or stopped with charm actions as follows:

```bash
juju run-action --wait docker-registry/0 stop
juju run-action --wait docker-registry/0 start
```

## Configuration

### Authentication

This charm supports basic (htpasswd) as well as token-based authentication.
Configure either method as follows:

```bash
juju config docker-registry \
  auth-basic-user='admin' \
  auth-basic-password='redrum'

juju config docker-registry \
  auth-token-issuer='auth.example.com' \
  auth-token-realm='myorg' \
  auth-token-root-certs='$(base64 /path/to/file)' \
  auth-token-service='myapp'
```

### Delete by digest

The recommended way to delete images from the registry is to use the `rmi`
action. If necessary, this charm can be configured to
[allow deletion][storage-delete] of blobs and manifests by digest by setting
the `storage-delete` config option to `true`:

```bash
juju config docker-registry storage-delete=true
```

[storage-delete]: https://docs.docker.com/registry/configuration/#delete

### Read-Only Mode

The registry can be switched to [read-only mode][storage-readonly] by setting
the `storage-read-only` config option to `true`:

```bash
juju config docker-registry storage-read-only=true
```

[storage-readonly]: https://docs.docker.com/registry/configuration/#readonly

This may be useful when performing maintenance or deploying an environment
with complex authentication requirements.

As an example, consider a scenario that requires unauthenticated pull
and authenticated push access to the registry. This can be achieved by
deploying this charm twice with the same storage backend (for example,
a Swift object storage cluster):

```bash
juju deploy docker-registry public --config <storage-swift-opts>
juju deploy docker-registry private --config <storage-swift-opts>
```

Configure the unauthenticated public registry to be read-only, and enable
authentication for the private registry:

```bash
juju config public storage-read-only=true
juju config private <auth-opts>
```

With a common storage backend and appropriate configuration, unauthenticated
public users have a read-only view of the images pushed by authenticated
private users.

### Swift Storage

The charm supports Swift configuration options that can be used to store
images in a Swift backend:

```bash
juju config docker-registry \
  storage-swift-authurl=<url> \
  storage-swift-container=<container> \
  storage-swift-password=<pass> \
  storage-swift-region=<region> \
  storage-swift-tenant=<tenant> \
  storage-swift-username=<user>
```

>Note: If any of the swift config options are set, they must all be set.

Also note that if the swift container is empty, requests to the registry may
return 503 errors like the following:

```
{"errors":[{"code":"UNAVAILABLE","message":"service unavailable","detail":"health check failed: please see /debug/health"}]}
```

Per https://github.com/docker/distribution/issues/2292, upload an empty file
called "files" at the root of the container to workaround the issue.

## Contact

The `docker-registry` charm is free and open source software created by the
~containers team at Canonical.
