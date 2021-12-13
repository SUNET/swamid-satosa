from satosa.micro_services.base import ResponseMicroService


class EPPNMapper(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eppn_attribute = config["eppn_attribute"]
        self.scope_attribute = config["scope_attribute"]
        self.eppn_prefix = config["eppn_prefix"]
        self.eppn_to_user_id = config["eppn_to_user_id"]

    def process(self, context, internal_data):
        prefix = self.eppn_prefix
        scope = internal_data.attributes[self.scope_attribute][0]
        eppns = internal_data.attributes[self.eppn_attribute]
        user_ids = [self.eppn_to_user_id.get(eppn) for eppn in eppns]
        user_ids_prefixed_scoped = [f"{prefix}{uid}@{scope}" for uid in user_ids]

        internal_data.attributes[self.eppn_attribute] = user_ids_prefixed_scoped
        return super().process(context, internal_data)
