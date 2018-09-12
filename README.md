Docker Registry
===============

The docker-registry provides storage and distribution of docker images.
See https://docs.docker.com/registry/ for details.

Build
-----
Requires charm tools to be installed. Then build the charm with:

    make build

Deploy
------

    juju deploy ./dist/builds/docker-registry

Charm supports reverse-proxying with haproxy and monitoring with nagios:

    juju add-relation docker-registry haproxy
    juju add-relation docker-registry nrpe-external-master

