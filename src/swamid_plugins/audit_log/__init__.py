"""
The audit-log micro-service runs after other micro-services,
in order to record what was sent to the target-service.
"""

from datetime import datetime
from json import dumps as serialize_to_json
from logging import getLogger as get_logger

from satosa.context import Context
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService


logger = get_logger(__name__)


class AuditLogger(ResponseMicroService):
    """
    Create audit log entries with:
    - Timestamp in local-time/CEST
    - IP-address of client
    - EntityID of user IdP
    - Eppn, assurance and accr of user IdP authentication
    - EntityID of SP
    - All attributes sent to SP
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_from_idp_state = config["data_from_idp_state"]

    def process(self, context: Context, internal_data: InternalData):
        issuer_internal_data = restore_internal_data(
            context.state, self.data_from_idp_state
        )
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip_address": context.http_headers.get("HTTP_X_REAL_IP"),
            "issuer_entity_id": issuer_internal_data.auth_info.issuer,
            "issuer_attributes": issuer_internal_data.attributes,
            "issuer_accr": issuer_internal_data.auth_info.auth_class_ref,
            "service_entity_id": internal_data.requester,
            "service_attributes": internal_data.attributes,
            "service_accr": internal_data.auth_info.auth_class_ref,
            "session_id": context.state.session_id,
        }
        entry_serialized = serialize_to_json(
            entry,
            sort_keys=False,
            indent=None,
            default=None,
            separators=(',', ':'),
        )
        logger.info(entry_serialized)
        return super().process(context, internal_data)


def restore_internal_data(state, key):
    state = state.pop(key, {})
    response_data = state.get("internal_data", {})
    data = InternalData.from_dict(response_data)
    return data
