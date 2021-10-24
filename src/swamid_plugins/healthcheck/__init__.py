import json

from satosa.micro_services.base import RequestMicroService
from satosa.response import Response


data = {
    "status": "ok",
}
ok_response = Response(message=json.dumps(data))


class HealthCheck(RequestMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_healthcheck(self, context):
        return ok_response

    def register_endpoints(self):
        return [("^healthcheck$", self._handle_healthcheck)]
