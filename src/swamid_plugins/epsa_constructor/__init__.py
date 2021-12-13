from satosa.micro_services.base import ResponseMicroService


class EPSAConstructor(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scope_attribute = config["scope_attribute"]
        self.epsa_attribute = config["epsa_attribute"]
        self.epsa_values = config["epsa_values"]

    def process(self, context, internal_data):
        scope = internal_data.attributes[self.scope_attribute][0]
        epsa_values = [f"{v}@{scope}" for v in self.epsa_values]

        internal_data.attributes[self.epsa_attribute] = epsa_values
        return super().process(context, internal_data)
