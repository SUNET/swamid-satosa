import time
from logging import getLogger as get_logger

import requests
from satosa.context import Context
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService


logger = get_logger(__name__)


class GroupsFromSCIM(ResponseMicroService):
    """
    Enrich the attribute set with a groups claim fetched from a SCIM API.

    The plugin queries a SCIM /Users endpoint filtered by userName (the
    subject identifier from the IdP) and extracts the group display names
    from the response.

    Authentication to the SCIM API is done via a GNAP (RFC 9635) grant
    from sunet-auth-server.  The plugin requests a bearer token using the
    ConfigFlow (pre-configured client key) and caches it until expiry.

    Example configuration:

      ```yaml
      module: swamid_plugins.groups.GroupsFromSCIM
      name: GroupsFromSCIM
      config:
        # Base URL of the SCIM API (no trailing slash)
        scim_base_url: "https://scim.example.com"

        # GNAP auth server transaction endpoint
        gnap_auth_url: "https://auth.example.com/transaction"

        # Pre-configured client key name on the auth server
        gnap_client_key: "my-scim-client"

        # Client certificate and key for mTLS proof (PEM file paths)
        gnap_client_cert: "/path/to/client.crt"
        gnap_client_key_file: "/path/to/client.key"

        # Access type to request (default: scim-api)
        gnap_access_type: "scim-api"

        # The internal attribute that holds the user identifier
        # used as the SCIM userName filter (default: subject_id)
        user_id_attribute: "subject_id"

        # The claim name to store the groups under (default: groups)
        groups_claim_name: "groups"
      ```
    """

    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scim_base_url = config["scim_base_url"].rstrip("/")
        self.user_id_attribute = config.get("user_id_attribute", "subject_id")
        self.groups_claim_name = config.get("groups_claim_name", "groups")

        # GNAP auth config
        self.gnap_auth_url = config["gnap_auth_url"]
        self.gnap_client_key = config["gnap_client_key"]
        self.gnap_client_cert = (
            config["gnap_client_cert"],
            config["gnap_client_key_file"],
        )
        self.gnap_access_type = config.get("gnap_access_type", "scim-api")

        # Token cache
        self._access_token: str | None = None
        self._token_expires_at: float = 0

    def process(self, context: Context, data: InternalData):
        user_ids = data.attributes.get(self.user_id_attribute, [])
        user_id = user_ids[0] if user_ids else data.subject_id

        groups = self._fetch_groups(user_id)
        if groups is not None:
            data.attributes[self.groups_claim_name] = groups

        log_ctx = {
            "message": "Processed groups enrichment",
            "user_id": user_id,
            "groups": groups,
            "groups_claim_name": self.groups_claim_name,
        }
        logger.info(log_ctx)

        return super().process(context, data)

    def _get_access_token(self) -> str | None:
        if self._access_token and time.time() < self._token_expires_at:
            return self._access_token

        grant_request = {
            "access_token": [
                {
                    "flags": ["bearer"],
                    "access": [{"type": self.gnap_access_type}],
                }
            ],
            "client": {"key": self.gnap_client_key},
        }

        try:
            response = requests.post(
                self.gnap_auth_url,
                json=grant_request,
                cert=self.gnap_client_cert,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.exception("Failed to obtain GNAP access token")
            return None

        data = response.json()
        token_response = data.get("access_token", {})
        self._access_token = token_response.get("value")
        expires_in = token_response.get("expires_in", 3600)
        # Refresh 60 seconds before actual expiry
        self._token_expires_at = time.time() + expires_in - 60

        return self._access_token

    @staticmethod
    def _escape_scim_filter_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _fetch_groups(self, user_id: str) -> list[str] | None:
        token = self._get_access_token()
        if not token:
            return None

        safe_user_id = self._escape_scim_filter_value(user_id)
        scim_filter = f'userName eq "{safe_user_id}"'
        url = f"{self.scim_base_url}/Users"
        params = {
            "attributes": "groups",
            "filter": scim_filter,
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/scim+json",
        }

        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
        except requests.RequestException:
            logger.exception("Failed to fetch groups from SCIM API for user %s", user_id)
            return None

        body = response.json()
        resources = body.get("Resources", [])
        if not resources:
            logger.warning("No SCIM user found for userName %s", user_id)
            return None

        user = resources[0]
        scim_groups = user.get("groups")
        if not scim_groups:
            return None

        return [g["display"] for g in scim_groups if "display" in g]
