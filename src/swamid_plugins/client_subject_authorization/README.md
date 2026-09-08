# Client subject authorization

This response microservice restricts selected clients to configured subject
identifiers. Clients absent from the file are not restricted.

```yaml
module: >-
  swamid_plugins.client_subject_authorization.ClientSubjectAuthorization
name: ClientSubjectAuthorization
config:
  allowed_subjects_file: /etc/satosa/allowed-subjects.json
```

The referenced JSON file maps exact client IDs to exact subject identifiers:

```json
{
  "example_client_id": [
    "user@example.org"
  ]
}
```

The file is read for every response so updates do not require restarting
SATOSA. Missing or invalid configuration is denied for all clients.
