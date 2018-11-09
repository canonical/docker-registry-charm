# Introduction

This charm provides storage and distribution of docker images. See
https://docs.docker.com/registry/ for details.

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

juju relate easyrsa docker-registry
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

### Proxied Registry

This charm supports an `http` proxy relation that allows operators to
control how the registry is exposed on the network. This is achieved by
relating to a proxy provider, such as `haproxy`:

```bash
juju deploy ~containers/docker-registry
juju deploy haproxy

juju relate haproxy docker-registry
juju expose haproxy
```

### Nagios Monitoring

This charm supports monitoring with nagios:

```bash
juju deploy ~containers/docker-registry
juju deploy nrpe --series bionic

juju relate docker-registry nrpe
```

## Actions

### Hosting Images

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
set. The image tag can be overriden by specifying the `tag` action paramenter.

### Starting/Stoping

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

## Contact

The `docker-registry` charm is free and open source software created by the
containers team at Canonical.
