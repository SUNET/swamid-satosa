from satosa.micro_services.base import ResponseMicroService


class InjectAttributes(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_values_map = config["attribute_values_map"]

    def process(self, context, internal_data):
        for attr, values in self.attribute_values_map.items():
            internal_data.attributes[attr] = values
        return super().process(context, internal_data)
