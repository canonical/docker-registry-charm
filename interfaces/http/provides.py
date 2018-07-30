from charmhelpers.core import hookenv
from charms.reactive import hook
from charms.reactive import RelationBase
from charms.reactive import scopes


class HttpProvides(RelationBase):
    scope = scopes.GLOBAL

    @hook('{provides:http}-relation-joined')
    def changed(self):
        self.set_state('{relation_name}.connected')

    @hook('{provides:http}-relation-changed')
    def changed(self):
        self.set_state('{relation_name}.changed')

    @hook('{provides:http}-relation-{broken,departed}')
    def disconnected(self):
        self.remove_state('{relation_name}.connected')

    def configure(self, port, **kwargs):
        relation_info = {
            'hostname': hookenv.unit_get('private-address'),
            'port': port,
        }
        relation_info.update(kwargs)
        self.set_remote(**relation_info)
        self.remove_state('{relation_name}.changed')
