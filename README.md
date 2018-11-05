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

### Integration with Kubernetes

See the Kubernetes private docker registry wiki for details.

### Nagios Monitoring

This charm supports monitoring with nagios:

```bash
juju deploy ~containers/docker-registry
juju deploy nrpe --series bionic

juju relate docker-registry nrpe
```

## Hosting Images

To make an image available in your private docker registry, you must tag and
push it. This charm provides an action that will do this:

```bash
juju run-action --wait docker-registry push \
  image=<image> pull=<True|False> tag=<optional-tag-name>
```

By default, this action will tag/push a local image so it is available from
your registry. If you specify `pull=True`, the action will first pull the
given `image` and subsequently tag/push it.

The default image tag is 'net_loc/name:version', where 'net_loc' is the
`http-host` config option or http[s]://[private-ip]:[port] if config is not
set. The image tag can be overriden by specifying the `tag` action paramenter.

## Configuration

### Using Basic Authentication

Basic auth support can be enabled by setting charm configuration options:

```bash
juju config docker-registry \
  auth-token-issuer=<name> \
  auth-token-realm=<location> \
  auth-token-root-certs=<cert-bundle> \
  auth-token-service=<server>
```

>Note: If any of the auth config options are set, they must all be set.

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
