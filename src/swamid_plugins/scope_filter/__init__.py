from re import match as match_regex

from satosa.micro_services.base import ResponseMicroService


class ScopeFilter(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_attributes = config.get("filter_attributes") or []

    def process(self, context, internal_data):
        issuer = internal_data.auth_info.issuer
        issuer_md = internal_data.metadata[issuer]
        allowed_scopes = issuer_md.get("sbibmd_scopes", [])

        for attribute in self.filter_attributes:
            values = internal_data.attributes.get(attribute) or []
            new_values = [
                value
                for value in values
                for _, attr_scope in [value.split('@', 2)]
                if any(
                    match(allowed_scope["text"], attr_scope)
                    for allowed_scope in allowed_scopes
                    for match in [scope_matchers[allowed_scope["regexp"]]]
                )
            ]
            if not new_values:
                internal_data.attributes.pop(attribute, None)
            else:
                internal_data.attributes[attribute] = new_values

        return super().process(context, internal_data)


def match_text(text, value):
    match = text == value
    return match


scope_matchers = {
    False: match_text,
    True: match_regex,
}
