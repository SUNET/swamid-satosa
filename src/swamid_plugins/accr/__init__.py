from logging import getLogger as get_logger

from satosa.micro_services.base import RequestMicroService
from satosa.context import Context
from satosa.internal import InternalData


logger = get_logger(__name__)


class StoreRequesterACCR(RequestMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_result = config["state_result"]

    def process(self, context: Context, internal_data: InternalData):
        context.state[self.state_result] = context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF)
        return super().process(context, internal_data)
