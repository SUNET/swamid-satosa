from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Unauthorized as UnauthorizedResponse


class EPPNMapperError(SATOSAError):
    pass


class EPPNMapper(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eppn_attribute = config["eppn_attribute"]
        self.scope_attribute = config["scope_attribute"]
        self.eppn_prefix = config["eppn_prefix"]
        self.eppn_to_user_id = config["eppn_to_user_id"]

        templates_dir_path = config["templates_dir_path"]
        self.tpl_env = Environment(loader=FileSystemLoader(templates_dir_path), autoescape=select_autoescape())

    def process(self, context, internal_data):
        prefix = self.eppn_prefix
        scope = internal_data.attributes[self.scope_attribute][0]
        eppns = internal_data.attributes[self.eppn_attribute]
        user_ids = [
            user_id
            for eppn in eppns
            for user_id in [self.eppn_to_user_id.get(eppn)]
            if user_id
        ]

        if not user_ids:
            requester = internal_data.requester
            requester_md = internal_data.metadata.get(requester)
            issuer = internal_data.auth_info.issuer
            issuer_md = internal_data.metadata.get(issuer)

            template = self.tpl_env.get_template("error-access.html.jinja2")
            content = template.render(
                attrs=internal_data.attributes,
                requester=requester,
                requester_md=requester_md,
                issuer=issuer,
                issuer_md=issuer_md,
                user_id=next(iter(eppns), None),
            )
            return UnauthorizedResponse(content)

        user_ids_prefixed_scoped = [f"{prefix}{uid}@{scope}" for uid in user_ids]

        internal_data.attributes[self.eppn_attribute] = user_ids_prefixed_scoped
        return super().process(context, internal_data)
