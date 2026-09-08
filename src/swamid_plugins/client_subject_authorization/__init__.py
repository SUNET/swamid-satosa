import json
from pathlib import Path

from satosa.exception import SATOSAAuthenticationError
from satosa.micro_services.base import ResponseMicroService


class ClientSubjectAuthorization(ResponseMicroService):
    """Authorize subjects for explicitly configured clients."""

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_subjects_file = Path(config["allowed_subjects_file"])

    def process(self, context, internal_data):
        client_id = internal_data.requester
        try:
            allowed_subjects = json.loads(self.allowed_subjects_file.read_text())
            if not isinstance(allowed_subjects, dict):
                raise TypeError
        except (OSError, TypeError, json.JSONDecodeError):
            raise SATOSAAuthenticationError(
                context.state,
                "Subject authorization configuration is unavailable",
            )

        if client_id not in allowed_subjects:
            return super().process(context, internal_data)

        subjects = allowed_subjects[client_id]
        if not isinstance(subjects, list) or not all(
            isinstance(subject, str) for subject in subjects
        ):
            raise SATOSAAuthenticationError(
                context.state,
                "Subject authorization configuration is unavailable",
            )

        if internal_data.subject_id not in subjects:
            raise SATOSAAuthenticationError(
                context.state,
                "Subject is not authorized for this client",
            )

        return super().process(context, internal_data)
