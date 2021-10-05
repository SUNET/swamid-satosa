from logging import getLogger as get_logger

from satosa.micro_services.base import RequestMicroService
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.context import Context
from satosa.internal import InternalData

from satosa.exception import SATOSAError


logger = get_logger(__name__)

REFEDS_MFA = "https://refeds.org/profile/mfa"

AL2_MFA_HI = "http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi"
AL3 = "http://www.swamid.se/policy/assurance/al3"
RAF_HI = "https://refeds.org/assurance/IAP/high"

ASSURANCES_MFA = [AL2_MFA_HI, AL3, RAF_HI]


class AssuranceRequirementsPerServiceCheckerError(SATOSAError):
    pass


class AssuranceRequirementsPerServiceChecker(RequestMicroService, ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_result = config["state_result"]
        self.error_url = config["error_url"]
        self.required_assurance_per_service = config["required_assurance_per_service"]
        self.required_assurance_default = self.required_assurance_per_service["default"]
        self.assurance_attribute = config["assurance_attribute"]

    def process(self, context: Context, internal_data: InternalData):
        is_request = bool(context.target_frontend)
        handler = self.process_request if is_request else self.process_response
        try:
            return handler(context, internal_data)
        except AssuranceRequirementsPerServiceCheckerError as e:
            context.state[self.state_result] = False
            context.state.delete = True
            logger.warning(e)
            return Redirect(self.error_url)

    def process_request(self, context: Context, internal_data: InternalData):
        requester = internal_data.requester
        required_assurance = self.required_assurance_per_service.get(requester, self.required_assurance_default)
        required_accr = REFEDS_MFA if required_assurance in ASSURANCES_MFA else None
        context.state[Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF] = required_accr
        context.state[self.state_result] = False
        return super().process(context, internal_data)

    def process_response(self, context: Context, internal_data: InternalData):
        requester = internal_data.requester
        assurances = internal_data.attributes.get(self.assurance_attribute)
        required_assurance = self.required_assurance_per_service.get(requester, self.required_assurance_default)

        if required_assurance not in assurances:
            error_context = {
                "message": "required assurance for service was not satisfied",
                "requester": requester,
                "required_assurance": required_assurance,
                "assurances": assurances,
            }
            raise AssuranceRequirementsPerServiceCheckerError(error_context)

        context.state[self.state_result] = True
        return super().process(context, internal_data)
