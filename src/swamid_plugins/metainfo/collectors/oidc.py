def collect_entity_metadata(mdstore, entity_id):
    metadata = {
        "display_name": get_display_name(mdstore, entity_id),
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


def get_display_name(mdstore, entity_id):
    display_name = mdstore.get("client_name")
    return display_name


def get_privacy_statement(mdstore, entity_id):
    privacy_statement = mdstore.get("policy_uri")
    return privacy_statement


def get_contacts(mdstore, entity_id):
    contacts = [
        contact
        for contact in [
            {
                "contact_type": "administrative",
                "email_address": [
                    "mailto:{contact}".format(contact=email)
                    for email in (mdstore.get("contacts") or [])
                ],
                "given_name": ""
            },
            {
                "contact_type": "technical",
                "email_address": [
                    "mailto:{contact}".format(contact=email)
                    for email in (mdstore.get("technical_contacts") or [])
                ],
                "given_name": ""
            },
            {
                "contact_type": "security",
                "email_address": [
                    "mailto:{contact}".format(contact=email)
                    for email in (mdstore.get("security_contacts") or [])
                ],
                "given_name": ""
            },
        ]
        if contact["email_address"]
    ]
    return contacts


def get_entity_categories(mdstore, entity_id):
    entity_categories_translation = {
        'research_and_scholarship': 'http://refeds.org/category/research-and-scholarship',
        'geant_coco': 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1',
    }
    entity_categories = [
        category
        for key, category in entity_categories_translation.items()
        if mdstore.get(key) == "True"
    ]
    return entity_categories


def get_supported_entity_categories(mdstore, entity_id):
    supported_entity_categories = []
    return supported_entity_categories


def get_assurance_certifications(mdstore, entity_id):
    assurance_certifications_translations = {
        'sirtfi': 'https://refeds.org/sirtfi',
    }
    assurance_certifications = [
        certification
        for key, certification in assurance_certifications_translations.items()
        if mdstore.get(key) == "True"
    ]
    return assurance_certifications


def get_registration_info(mdstore, entity_id):
    registration_info = {}
    return registration_info


def get_error_url(mdstore, entity_id):
    error_url = mdstore.get("error_url", [])
    return error_url


def get_sbibmd_scopes(mdstore, entity_id):
    scopes = list(mdstore.get("sbibmd_scopes", []))
    return scopes
