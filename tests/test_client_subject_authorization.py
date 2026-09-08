import json
from tempfile import TemporaryDirectory
from unittest import TestCase

from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.internal import InternalData
from satosa.state import State

from swamid_plugins.client_subject_authorization import (
    ClientSubjectAuthorization,
)


class TestClientSubjectAuthorization(TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.allowed_subjects_file = f"{self.temp_dir.name}/allowed-subjects.json"
        with open(self.allowed_subjects_file, "w") as file:
            json.dump(
                {"protected-client": ["allowed-subject"]},
                file,
            )
        config = {
            "allowed_subjects_file": self.allowed_subjects_file,
        }
        self.plugin = ClientSubjectAuthorization(
            config,
            "ClientSubjectAuthorization",
            "https://proxy.example.org/",
        )
        self.plugin.next = lambda context, data: (context, data)
        self.context = Context()
        self.context.state = State()

    def test_unconfigured_client_is_unchanged(self):
        data = InternalData(
            requester="other-client",
            subject_id="any-subject",
        )

        _, result = self.plugin.process(self.context, data)

        self.assertIs(result, data)

    def test_configured_client_allows_listed_subject(self):
        data = InternalData(
            requester="protected-client",
            subject_id="allowed-subject",
        )

        _, result = self.plugin.process(self.context, data)

        self.assertIs(result, data)

    def test_configured_client_denies_other_subject(self):
        data = InternalData(
            requester="protected-client",
            subject_id="other-subject",
        )

        with self.assertRaises(SATOSAAuthenticationError):
            self.plugin.process(self.context, data)

    def test_configured_client_denies_when_file_is_unavailable(self):
        self.plugin.allowed_subjects_file = self.plugin.allowed_subjects_file.with_name(
            "missing.json"
        )
        data = InternalData(
            requester="protected-client",
            subject_id="allowed-subject",
        )

        with self.assertRaises(SATOSAAuthenticationError):
            self.plugin.process(self.context, data)
