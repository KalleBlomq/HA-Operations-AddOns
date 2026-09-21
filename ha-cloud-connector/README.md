# HA Cloud Connector

This Home Assistant local add-on makes outbound HTTPS polling requests to the
V2 gateway. It uses the Supervisor-provided `SUPERVISOR_TOKEN` to read Home
Assistant (`homeassistant_api: true`); do not create a long-lived HA token.

## Install and configure

1. Add this folder to a Home Assistant add-on repository (or copy it into the
   local add-ons directory) and build the add-on.
2. Onboard the instance through `POST /api/management/instances`.
3. Set `gateway_url`, returned `instance_id`, and the one-time
   `connector_token` in add-on options.
4. Keep `verify_ssl: true` for production endpoints, start the add-on, and
   verify its log reports startup without credentials or payloads.

The connector implements only the seven allowlisted read operations. It has no
Home Assistant service-call or configuration-write implementation.
