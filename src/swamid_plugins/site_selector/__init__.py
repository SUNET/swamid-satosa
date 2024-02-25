from re import match as match_regex

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService


class Error(SATOSAError):
    ...


class SiteSelector(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO: validate configuration format
        self.access_rules = config.get("access_rules", {})
        self.access_rules_default = (
            self.access_rules.pop("", None)
            or self.access_rules.pop("default", None)
        )

    def process(self, context, internal_data):
        service_id = internal_data.requester
        access_rules_for_service = (
            self.access_rules.get(service_id)
            or self.access_rules_default
        )

        # evaluate each rule set for this particular service
        for rule in access_rules_for_service:
            result = evaluate_rule(rule, internal_data.attributes)
            # if a rule was satisfied, continue processing the response
            if result:
                return super().process(context, internal_data)

        # no rule was successful; abort processing the response any further
        error_context = {
            "message": "Failed to satisfy any rule for accessing the service.",
            "service": service_id,
            "rules": access_rules_for_service,
        }
        raise Error(error_context)


def evaluate_rule(rule, attributes):
    regex = rule["match"]
    attr = rule["attribute"]
    attr_values = attributes.get(attr, [])
    satisfied = any(
        match_regex(regex, v)
        for v in attr_values
    )
    return satisfied
