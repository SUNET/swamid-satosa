from unittest import TestCase

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from swamid_plugins.site_selector import SiteSelector
from swamid_plugins.site_selector import Error as SiteSelectorError


class TestProcessing(TestCase):
    def setUp(self):
        self.config = {
            "access_rules": {
                "service_id_x": [
                    {
                        "attribute": "eppn",
                        "match": "^[a-z0-9]+@x.example.org$",
                    }
                ],
                "service_id_y": [
                    {
                        "attribute": "eppn",
                        "match": "^[a-z0-9]+@y.example.org$",
                    }
                ],
                "": [
                    {
                        "attribute": "eppn",
                        "match": "^[a-z0-9]+@example.org$",
                    }
                ],
            },
        }

        self.plugin = SiteSelector(self.config, "SiteSelector", "https://proxy.example.org/")
        self.plugin.next = lambda context, internal_data: (context, internal_data)

        self.context = Context()
        self.context.state = State()

    def test_process_authorized(self):
        internal_data = InternalData(
            requester="service_id_x",
            attributes = {"eppn": ["foo@x.example.org"]},
        )
        context, data = self.plugin.process(self.context, internal_data)

    def test_process_authorized_default(self):
        internal_data = InternalData(
            requester="service_id_z",
            attributes = {"eppn": ["foo@example.org"]},
        )
        context, data = self.plugin.process(self.context, internal_data)

    def test_process_unauthorized(self):
        internal_data = InternalData(
            requester="service_id_y",
            attributes = {"eppn": ["foo@example.org"]},
        )
        with self.assertRaises(SiteSelectorError):
            self.plugin.process(self.context, internal_data)
