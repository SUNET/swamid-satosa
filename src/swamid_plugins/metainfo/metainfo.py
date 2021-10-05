"""Extract metadata information for the requester and issuer."""

from satosa.micro_services.base import ResponseMicroService
from satosa.micro_services.base import RequestMicroService

from .collectors import collect_oidc_entity_metadata
from .collectors import collect_saml_entity_metadata

import re


KEY_STATE = "MetaInfoService"
KEY_ISSUER_METADATA = "metadata_store"
KEY_SAML_REQUESTER_METADATA = "metadata_store"
KEY_OIDC_REQUESTER_METADATA = "requester_metadata"
UUID4HEX = re.compile(
    "^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z", re.I
)


def is_oidc_client(entity_id):
    result = entity_id.startswith("APP-") or bool(UUID4HEX.match(entity_id))
    return result


def collect_entity_metadata(mdstore, metadata, entity_id):
    entity_metadata = (
        {}
        if not mdstore
        else collect_oidc_entity_metadata(mdstore, entity_id)
        if is_oidc_client(entity_id)
        else collect_saml_entity_metadata(mdstore, entity_id)
    )
    return entity_metadata


def update_metadata_with_entity(mdstore, metadata, entity_id):
    entity_metadata = collect_entity_metadata(mdstore, metadata, entity_id)
    updated_metadata = (
        {**metadata, entity_id: entity_metadata} if entity_metadata else metadata
    )
    return updated_metadata


class _MetaInfoService:
    """
    Extract metadata info for the requester (on request) and the issuer (on response)
    """

    def process(self, context, internal_data):
        metadata = self.extract_metadata_state(context.state)
        entity_id = self.get_entity_id(internal_data)
        mdstore = self.get_metadata_store(context, entity_id)

        has_been_processed = entity_id in metadata
        metadata_new = (
            update_metadata_with_entity(
                mdstore=mdstore,
                metadata=metadata,
                entity_id=entity_id,
            )
            if not has_been_processed
            else metadata
        )

        internal_data.metadata = metadata_new
        self.update_metadata_state(context.state, metadata_new)
        return super().process(context, internal_data)


class MetaInfoRequester(_MetaInfoService, RequestMicroService):
    """
    Extract metadata info for the requester.

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfoRequester
      name: MetaInfoRequester
      ```
    """

    def extract_metadata_state(self, state):
        metadata = {}
        return metadata

    def update_metadata_state(self, state, metadata):
        state[KEY_STATE] = {"metadata": metadata}

    def get_metadata_store(self, context, entity_id):
        md = context.get_decoration(
            KEY_OIDC_REQUESTER_METADATA
            if is_oidc_client(entity_id)
            else KEY_SAML_REQUESTER_METADATA
        )
        return md

    def get_entity_id(self, internal_data):
        entity_id = internal_data.requester
        return entity_id


class MetaInfoIssuer(_MetaInfoService, ResponseMicroService):
    """
    Extract metadata info for the issuer.

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfoIssuer
      name: MetaInfoIssuer
      ```
    """

    def extract_metadata_state(self, state):
        metadata = state.pop(KEY_STATE, {}).get("metadata", {})
        return metadata

    def update_metadata_state(self, state, metadata):
        state[KEY_STATE] = {"metadata": metadata}

    def get_metadata_store(self, context, entity_id):
        md = context.get_decoration(KEY_ISSUER_METADATA)
        return md

    def get_entity_id(self, internal_data):
        entity_id = internal_data.auth_info.issuer
        return entity_id


class MetaInfoRequesterOnResponse(MetaInfoIssuer):
    """
    Extract metadata info for the requester.

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfoRequesterOnResponse
      name: MetaInfoRequesterOnResponse
      ```
    """

    def update_metadata_state(self, state, metadata):
        state[KEY_STATE] = {"metadata": metadata}

    def get_entity_id(self, internal_data):
        entity_id = internal_data.requester
        return entity_id
