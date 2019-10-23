import os
import sys
from unittest.mock import MagicMock

# mock dependencies which we don't care about covering in our tests
ch = MagicMock()
sys.modules['charmhelpers'] = ch
sys.modules['charmhelpers.contrib'] = ch.contrib
sys.modules['charmhelpers.contrib.hahelpers'] = ch.contrib.hahelpers
sys.modules['charmhelpers.contrib.hahelpers.cluster'] = ch.contrib.hahelpers.cluster
sys.modules['charmhelpers.core'] = ch.core
charms = MagicMock()
sys.modules['charms'] = charms
sys.modules['charms.layer'] = charms.layer
sys.modules['charms.leadership'] = charms.leadership
sys.modules['charms.reactive'] = charms.reactive
sys.modules['charms.reactive.helpers'] = charms.reactive.helpers

os.environ['JUJU_MODEL_UUID'] = 'test-1234'
