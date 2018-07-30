import socket

from charms.reactive import hook
from charms.reactive import RelationBase
from charms.reactive import scopes


class HttpRequires(RelationBase):
    scope = scopes.UNIT

    @hook('{requires:http}-relation-{joined,changed}')
    def changed(self):
        conv = self.conversation()
        if conv.get_remote('port'):
            # this unit's conversation has a port, so
            # it is part of the set of available units
            conv.set_state('{relation_name}.available')

    @hook('{requires:http}-relation-{departed,broken}')
    def broken(self):
        conv = self.conversation()
        conv.remove_state('{relation_name}.available')

    def services(self):
        """
        Returns a list of available HTTP services and their associated hosts
        and ports.

        The return value is a list of dicts of the following form::

            [
                {
                    'service_name': name_of_service,
                    'hosts': [
                        {
                            'hostname': address_of_host,
                            'port': port_for_host,
                            'path': path_for_proxying_host,
                        },
                        # ...
                    ],
                },
                # ...
            ]
        """
        services = {}
        for conv in self.conversations():
            service_name = conv.scope.split('/')[0]
            service = services.setdefault(service_name, {
                'service_name': service_name,
                'hosts': [],
            })
            host = conv.get_remote('hostname')
            if host:
                try:
                    socket.gethostbyname(host)
                except socket.error:
                    host = conv.get_remote('private-address')
            else:
                host = conv.get_remote('private-address')
            port = conv.get_remote('port')
            path = conv.get_remote('path')
            if host and port:
                service['hosts'].append({
                    'hostname': host,
                    'port': port,
                    'path': path,
                })
        return [s for s in services.values() if s['hosts']]
