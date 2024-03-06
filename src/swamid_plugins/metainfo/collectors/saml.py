def collect_entity_metadata(mdstore, entity_id, langs):
    metadata = {
        "display_names": get_display_names_lang(mdstore, entity_id, langs),
        "logo": get_logo(mdstore, entity_id),
        "privacy_statement": get_privacy_statement(mdstore, entity_id),
        "contacts": get_contacts(mdstore, entity_id),
        "entity_categories": get_entity_categories(mdstore, entity_id),
        "supported_entity_categories": get_supported_entity_categories(mdstore, entity_id),
        "assurance_certifications": get_assurance_certifications(mdstore, entity_id),
        "registration_info": get_registration_info(mdstore, entity_id),
        "error_url": get_error_url(mdstore, entity_id),
        "sbibmd_scopes": get_sbibmd_scopes(mdstore, entity_id),
    }
    return metadata


def get_display_names_lang(mdstore, entity_id, langs=None):
    uiinfos = mdstore.mdui_uiinfo(entity_id)
    cls = "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
    elements = list((
        element
        for uiinfo in uiinfos
        for element_key, elements in uiinfo.items()
        if element_key != "__class__"
        for element in elements
        if element.get("__class__") == cls
    ))
    list(map(lambda name: name.pop("__class__", None), elements))
    elements = list(filter(lambda x: x["lang"] in langs, elements))
    return elements


def get_logo(mdstore, entity_id):
    logos = list(mdstore.mdui_uiinfo_logo(entity_id))
    list(map(lambda logo: logo.pop("__class__", None), logos))
    return logos


def get_privacy_statement(mdstore, entity_id):
    privacy_statement = next(
        mdstore.mdui_uiinfo_privacy_statement_url(entity_id, langpref="en"), None
    )
    return privacy_statement


def get_contacts(mdstore, entity_id):
    contacts = list(mdstore.contact_person_data(entity_id))
    return contacts


def get_entity_categories(mdstore, entity_id):
    entity_categories = mdstore.entity_categories(entity_id)
    return entity_categories


def get_supported_entity_categories(mdstore, entity_id):
    supported_entity_categories = mdstore.supported_entity_categories(entity_id)
    return supported_entity_categories


def get_assurance_certifications(mdstore, entity_id):
    assurance_certifications = list(mdstore.assurance_certifications(entity_id))
    return assurance_certifications


def get_registration_info(mdstore, entity_id):
    registration_info = mdstore.registration_info(entity_id) or {}
    return registration_info


def get_error_url(mdstore, entity_id):
    error_url = [
        idpsso['error_url']
        for idpsso in mdstore[entity_id].get('idpsso_descriptor', [])
        if 'error_url' in idpsso
    ]
    return error_url


def get_sbibmd_scopes(mdstore, entity_id):
    scopes = list(mdstore.sbibmd_scopes(entity_id, typ="idpsso_descriptor"))
    return scopes
