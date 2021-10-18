from logging import getLogger as get_logger

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Unauthorized as UnauthorizedResponse


logger = get_logger(__name__)


class AttributeCheckerError(SATOSAError):
    pass


class AttributeChecker(ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_result = config["state_result"]
        self.attributes_strategy = {'all': all, 'any': any}[config.get("attributes_strategy", "all")]
        self.attribute_values_strategy = {'all': all, 'any': any}[config.get("attribute_values_strategy", "any")]
        self.allowed_attributes = config.get("allowed_attributes")
        self.user_id_attribute = config["user_id_attribute"]

        templates_dir_path = config["templates_dir_path"]
        self.tpl_env = Environment(loader=FileSystemLoader(templates_dir_path), autoescape=select_autoescape())

    def process(self, context, internal_data):
        try:
            return self._process(context, internal_data)
        except AttributeCheckerError as e:
            context.state[self.state_result] = False
            context.state.delete = True
            logger.warning(e)

            requester = internal_data.requester
            requester_md = internal_data.metadata.get(requester)
            issuer = internal_data.auth_info.issuer
            issuer_md = internal_data.metadata.get(issuer)
            user_id = internal_data.attributes.get(self.user_id_attribute, [None])[0]

            template = self.tpl_env.get_template("error-access.html.jinja2")
            content = template.render(
                attrs=internal_data.attributes,
                requester=requester,
                requester_md=requester_md,
                issuer=issuer,
                issuer_md=issuer_md,
                user_id=user_id,
            )
            return UnauthorizedResponse(content)

    def _process(self, context, internal_data):
        context.state[self.state_result] = False
        is_authorized = self.attributes_strategy(
            self.attribute_values_strategy(
                value in values
                for value in internal_data.attributes.get(attr, [])
            )
            for attr, values in self.allowed_attributes.items()
        )

        if not is_authorized:
            error_context = {
                'message': 'User is not authorized to access this service.',
                'allowed_attributes': list(self.allowed_attributes.keys()),
                'attributes': internal_data.attributes.keys(),
                'attributes_strategy': self.attributes_strategy.__name__,
                'attribute_values_strategy': self.attribute_values_strategy.__name__,
            }
            raise AttributeCheckerError(error_context)

        context.state[self.state_result] = True
        return super().process(context, internal_data)
