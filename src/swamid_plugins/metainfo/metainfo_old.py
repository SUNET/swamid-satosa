"""Extract info from IdP metadata."""
from satosa.micro_services.base import ResponseMicroService


ASSURANCE_CERTIFICATION = "urn:oasis:names:tc:SAML:attribute:assurance-certification"


def gather_entities_metadata(mdstore, entity_ids):
    metadata = {
        entity_id: gather_entity_metadata(mdstore, entity_id=entity_id)
        for entity_id in entity_ids
    }
    return metadata


def gather_entity_metadata(mdstore, entity_id):
    metadata = {
        "display_name": (
            next(mdstore.mdui_uiinfo_display_name(entity_id), None)
            or mdstore.name(entity_id)
        ),
        "privacy_statement": next(
            mdstore.mdui_uiinfo_privacy_statement_url(entity_id), None
        ),
        "contacts": list(mdstore.contact_person_data(entity_id)),
        "entity_categories": mdstore.entity_categories(entity_id),
        "supported_entity_categories": mdstore.supported_entity_categories(entity_id),
        "assurance_certifications": list(mdstore.assurance_certifications(entity_id)),
        "registration_info": (mdstore.registration_info(entity_id) or {}),
    }
    return metadata


class MetaInfo(ResponseMicroService):
    """
    Metadata info extracting micro_service

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfo
      name: MetaInfo
      ```
    """

    def process(self, context, internal_data):
        mdstore = context.internal_data["metadata_store"]
        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
        metadata = gather_entities_metadata(mdstore, entity_ids=[issuer, requester])
        internal_data.metadata = metadata
        return super().process(context, internal_data)
