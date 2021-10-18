from datetime import datetime
from json import dumps as serialize_to_json
from logging import getLogger as get_logger
from re import compile as compile_regex
from re import escape as escape_regex
from urllib.parse import quote_plus as encode_url

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import RequestMicroService
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Unauthorized as UnauthorizedResponse


logger = get_logger(__name__)

REFEDS_MFA = "https://refeds.org/profile/mfa"

AL2_MFA_HI = "http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi"
AL3 = "http://www.swamid.se/policy/assurance/al3"
RAF_HI = "https://refeds.org/assurance/IAP/high"

ASSURANCES_MFA = [AL2_MFA_HI, AL3, RAF_HI]


class AssuranceRequirementsPerServiceCheckerError(SATOSAError):
    def __init__(self, error_context, *args, **kwargs):
        message = serialize_to_json(error_context)
        super().__init__(message)
        self.error_context = error_context


class AssuranceRequirementsPerServiceChecker(RequestMicroService, ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_result = config["state_result"]
        self.required_assurance_per_service = config["required_assurance_per_service"]
        self.required_assurance_default = self.required_assurance_per_service["default"]
        self.assurance_attribute = config["assurance_attribute"]

        templates_dir_path = config["templates_dir_path"]
        self.tpl_env = Environment(loader=FileSystemLoader(templates_dir_path), autoescape=select_autoescape())

    def process(self, context: Context, internal_data: InternalData):
        is_request = bool(context.target_frontend)
        handler = self.process_request if is_request else self.process_response
        try:
            return handler(context, internal_data)
        except AssuranceRequirementsPerServiceCheckerError as e:
            context.state[self.state_result] = False
            context.state.delete = True
            logger.warning(e)

            required_assurance = e.error_context.get("required_assurance")
            user_assurances = e.error_context.get("assurances")

            requester = internal_data.requester
            requester_md = internal_data.metadata.get(requester)
            issuer = None if is_request else internal_data.auth_info.issuer
            issuer_md = {} if is_request else internal_data.metadata.get(issuer)

            error_url_from_md = next(iter(issuer_md["error_url"]), None)
            error_url_rendered = None
            if error_url_from_md:
                error_url_replacements = {
                    "ERRORURL_CODE": "AUTHORIZATION_FAILURE",
                    "ERRORURL_TS": str(int(datetime.utcnow().timestamp())),
                    "ERRORURL_RP": encode_url(requester),
                    "ERRORURL_TID": context.state.session_id,
                    "ERRORURL_CTX": encode_url(required_assurance),
                }
                error_url_pattern = compile_regex("|".join(escape_regex(k) for k in error_url_replacements.keys()))
                error_url_rendered = error_url_pattern.sub(lambda m: error_url_replacements[m.group(0)], error_url_from_md)

            template = self.tpl_env.get_template("error-assurance.html.jinja2")
            content = template.render(
                attrs=internal_data.attributes,
                requester=requester,
                requester_md=requester_md,
                issuer=issuer,
                issuer_md=issuer_md,
                error_url=error_url_rendered,
                required_assurance=required_assurance,
                user_assurances=user_assurances,
            )
            return UnauthorizedResponse(content)

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
