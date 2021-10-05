from logging import getLogger as get_logger

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from satosa.exception import SATOSAError


logger = get_logger(__name__)

SWAMID_AUTHORITY = "http://www.swamid.se/"

REFEDS_MFA = "https://refeds.org/profile/mfa"

AL1 = "http://www.swamid.se/policy/assurance/al1"
AL2 = "http://www.swamid.se/policy/assurance/al2"
AL2_MFA_HI = "http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi"
AL3 = "http://www.swamid.se/policy/assurance/al3"

ASSURANCES_FILTER = [AL1, AL2, AL2_MFA_HI, AL3]
ASSURANCES_MFA = [AL2_MFA_HI, AL3]


class SWAMIDAssuranceChecker(ResponseMicroService):
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.assurance_attribute = config["assurance_attribute"]

    def process(self, context: Context, internal_data: InternalData):
        issuer = internal_data.auth_info.issuer
        metadata = internal_data.metadata.get(issuer, {})
        authority = metadata.get("registration_info", {}).get("registration_authority")
        assurance_certifications = metadata.get("assurance_certifications", [])
        received_accr = internal_data.auth_info.auth_class_ref
        assurances = internal_data.attributes.get(self.assurance_attribute, [])

        assurances_set = set(assurances)

        # SWAMID assurances we care about
        for assurance in ASSURANCES_FILTER:

            # IdP signaled this assurance for user
            if assurance in assurances_set:

                # IdP is not a SWAMID IdP
                if authority != SWAMID_AUTHORITY:
                    msg = "registrationAuthority of {} is not {} (was {}), {} assurance removed".format(issuer, SWAMID_AUTHORITY, authority, assurance)
                    logger.debug(msg)
                    assurances_set.remove(assurance)

                # IdP does not have assurence in assurance_certifications
                elif assurance not in assurance_certifications:
                    msg = "IdP {} does not have {} in its assurance-certification, assurance removed".format(issuer, assurance)
                    logger.debug(msg)
                    assurances_set.remove(assurance)

        # Remove assurances requiring MFA is MFA was not used
        if received_accr != REFEDS_MFA:
            for assurance in ASSURANCES_MFA:
                if assurance in assurances_set:
                    msg = "IdP {} claimed assurance {} but MFA was not used, assurance removed".format(issuer, assurance)
                    logger.debug(msg)
                    assurances_set.remove(assurance)

        internal_data.attributes[self.assurance_attribute] = list(assurances_set)
        return super().process(context, internal_data)
