from logging import getLogger as get_logger

from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from satosa.exception import SATOSAError


logger = get_logger(__name__)


class AttributeCheckerError(SATOSAError):
    pass


class AttributeChecker(ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_url = config["error_url"]
        self.state_result = config["state_result"]
        self.attributes_strategy = {'all': all, 'any': any}[config.get("attributes_strategy", "all")]
        self.attribute_values_strategy = {'all': all, 'any': any}[config.get("attribute_values_strategy", "any")]
        self.allowed_attributes = config.get("allowed_attributes")

    def process(self, context, internal_data):
        try:
            return self._process(context, internal_data)
        except AttributeCheckerError as e:
            context.state[self.state_result] = False
            context.state.delete = True
            logger.warning(e)
            return Redirect(self.error_url)

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
