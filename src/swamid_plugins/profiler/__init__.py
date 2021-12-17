from base64 import urlsafe_b64encode as base64_urlsafe_encode
from base64 import urlsafe_b64decode as base64_urlsafe_decode
from collections import defaultdict
from json import dumps as json_dumps
from json import loads as json_loads
from logging import getLogger as get_logger
from urllib.parse import urlencode

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from saml2.saml import NAMEID_FORMAT_PERSISTENT

from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.response import Unauthorized as UnauthorizedResponse
from satosa.response import ServiceError as ServiceErrorResponse


logger = get_logger(__name__)


class ProfilerError(SATOSAError):
    pass


class ProfilerAuthzError(ProfilerError):
    pass


class Profiler(ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.internal_attributes = internal_attributes["attributes"]
        self.allowed_to_change_accr = config["allowed"].get("accr")
        self.allowed_to_change_name_id = config["allowed"].get("name_id")
        self.allowed_attributes = config["allowed"].get("attributes") or []
        self.attributes_strategy = config["allowed"].get("attributes_strategy", "replace_discard")
        self.profile_form_url = config.get("profile_form_url")
        self.response_endpoint = config.get("response_endpoint")
        self.requester_accr_state = config.get("requester_accr_state")
        self.data_from_idp_state = config.get("data_from_idp_state")
        self.authz_checks = config.get("authz_checks", [])

        templates_dir_path = config["templates_dir_path"]
        self.tpl_env = Environment(loader=FileSystemLoader(templates_dir_path), autoescape=select_autoescape())

    def register_endpoints(self):
        url_map = [("^{}.*$".format(self.response_endpoint), self.handle_response)]
        return url_map

    def process(self, context, internal_data):
        try:
            self._authorize(context)
        except ProfilerAuthzError as e:
            context.state.delete = True
            logger.warning(e)
            template = self.tpl_env.get_template("error-profiler-access.html.jinja2")
            content = template.render()
            return UnauthorizedResponse(content)
        except Exception as e:
            context.state.delete = True
            logger.error(e)
            template = self.tpl_env.get_template("error.html.jinja2")
            content = template.render()
            return ServiceErrorResponse(content)

        store_internal_data(
            context.state, self.data_from_idp_state, internal_data.to_dict()
        )
        requester_accr = context.state.get(self.requester_accr_state)

        # XXX TODO render with jinja2
        query_string_params = {}
        if requester_accr:
            query_string_params["authncontext"] = requester_accr[0]
        query_string = urlencode(query_string_params)
        return Redirect(self.profile_form_url + f'?{query_string}')

    def handle_response(self, context):
        try:
            internal_data = restore_internal_data(
                context.state, self.data_from_idp_state
            )
            self._authorize(context)
        except ProfilerAuthzError as e:
            context.state.delete = True
            logger.warning(e)
            template = self.tpl_env.get_template("error-profiler-access.html.jinja2")
            content = template.render()
            return UnauthorizedResponse(content)
        except Exception as e:
            context.state.delete = True
            logger.error(e)
            template = self.tpl_env.get_template("error.html.jinja2")
            content = template.render()
            return ServiceErrorResponse(content)

        store_internal_data(
            context.state, self.data_from_idp_state, internal_data.to_dict()
        )
        return self._handle_response(context, internal_data)

    def _authorize(self, context):
        is_authorized = all(
            context.state.get(check)
            for check in self.authz_checks
        )
        if not is_authorized:
            error_context = {
                'message': 'User is not authorized to access this service.',
                'is_authorized': is_authorized,
                'authz_checks': self.authz_checks,
            }
            raise ProfilerAuthzError(error_context)

        return True

    def _handle_response(self, context, internal_data):
        if self.allowed_to_change_accr:
            internal_data.auth_info.auth_class_ref = (
                context.request.get('authncontext')
                or internal_data.auth_info.auth_class_ref
            )

        if self.allowed_attributes:
            new_attributes = dict(
                convert_input_to_internal_attr[attr](attr, value)
                for attr, value in context.request.items()
                if attr in self.allowed_attributes
            )
            fn_attributes_strategy = attributes_strategy[self.attributes_strategy]
            internal_data.attributes = fn_attributes_strategy(
                new_attributes, internal_data.attributes
            )

        if self.allowed_to_change_name_id:
            internal_data.subject_id = (
                context.request.get("principal_name")
                or internal_data.subject_id
            )
            internal_data.subject_type = NAMEID_FORMAT_PERSISTENT

        return super().process(context, internal_data)


def replace_discard(new_attrs, issuer_attrs):
    return new_attrs


def replace_keep(new_attrs, issuer_attrs):
    return {**issuer_attrs, **new_attrs}


def merge_discard(new_attrs, issuer_attrs):
    merged_attributes = {
        attr: list(set(*issuer_attrs.get(attr, []), *values))
        for attr, values in new_attrs.items()
    }
    return merged_attributes


def merge_keep(new_attrs, issuer_attrs):
    merged_attributes = {
        attr: list(set(*issuer_attrs.get(attr, []), *values))
        for attr, values in new_attrs.items()
    }
    return {**issuer_attrs, **merged_attributes}


attributes_strategy = {
    "replace_discard": replace_discard,
    "replace_keep": replace_keep,
    "merge_discard": merge_discard,
    "merge_keep": merge_keep,
}


def convert_single_value_to_internal_attr(attr, value):
    return (attr, [value])


def convert_flat_format_value_to_internal_attr(separator, attr, value):
    return (attr, value.split(separator))


def convert_semicolon_flat_format_value_to_internal_attr(attr, value):
    return convert_flat_format_value_to_internal_attr(';', attr, value)


convert_input_to_internal_attr = defaultdict(
    lambda: convert_single_value_to_internal_attr,
    {
        'assurance': convert_semicolon_flat_format_value_to_internal_attr,
        'entitlement': convert_semicolon_flat_format_value_to_internal_attr,
    },
)


def store_internal_data(state, key, value):
    state[key] = {"internal_data": value}


def restore_internal_data(state, key):
    state = state.pop(key, {})
    response_data = state.get("internal_data", {})
    data = InternalData.from_dict(response_data)
    return data


def serialize_payload(payload):
    serialized = json_dumps(payload)
    encoded = serialized.encode("utf-8")
    b64encoded = base64_urlsafe_encode(encoded)
    encoded = b64encoded.decode("utf-8")
    return encoded


def deserialize_payload(payload):
    try:
        b64decoded = base64_urlsafe_decode(payload)
        decoded = b64decoded.decode("utf-8")
        deserialized = json_loads(decoded)
    except Exception as e:
        error_context = {
            "message": "Cannot decode data to expected format",
            "payload": payload,
            "exception": str(e),
        }
        logger.error(error_context)
        raise ProfilerError(error_context)
    else:
        return deserialized
