from logging import getLogger as get_logger

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData


logger = get_logger(__name__)


class MFAFlagger(ResponseMicroService):
    """
    Set attribute that signals MFA was performed.

    The attribute is set when:
    - the AuthnContextClassRef returned by the IdP is one of the accepted
      AuthnContextClassRefs that signal MFA, or
    - the IdP belongs to the IdP list that signals that these IdPs always perform MFA


    Example configuration:

      ```yaml
      module: swamid_plugins.mfa.MFAFlagger
      name: MFAFlagger
      config:
        # the name of the attribute that signals that MFA was performed
        mfa_attr_name: "mfa_verified"

        # the value to set this attribute to when MFA was performed
        mfa_attr_value: "1"

        # the list of AuthnContextClassRefs that signal MFA
        mfa_accepted_accrs:
          - "https://refeds.org/profile/mfa"

        # the list of IdP entityIDs that are assumed to always perform MFA
        mfa_idps:
          - "https://idp.sunet.se/idp"
      ```
    """

    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mfa_attr_name = config["mfa_attr_name"]
        self.mfa_attr_value = config["mfa_attr_value"]
        self.mfa_accepted_accrs = config["mfa_accepted_accrs"]
        self.mfa_idps = config["mfa_idps"]

    def process(self, context: Context, data: InternalData):
        sp = data.requester
        idp = data.auth_info.issuer

        if (
            data.auth_info.auth_class_ref in self.mfa_accepted_accrs
            or idp in self.mfa_idps
        ):
            data.attributes[self.mfa_attr_name] = [self.mfa_attr_value]

        log_ctx = {
            "message": "Processed mfa check",
            "config": {
                "mfa_accepted_accrs": self.mfa_accepted_accrs,
                "mfa_idps": self.mfa_idps,
                "mfa_attr_name": self.mfa_attr_name,
                "mfa_attr_value": self.mfa_attr_value,
            },
            "sp": sp,
            "idp": idp,
            "set_value": data.attributes.get(self.mfa_attr_name),
        }
        logger.info(log_ctx)

        return super().process(context, data)
