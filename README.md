# HA Operations Add-ons

Home Assistant add-on repository for the read-only HA Operations Agent connector.

## Add repository

`https://github.com/KalleBlomq/HA-Operations-AddOns`

The connector initiates outbound HTTPS only and exposes no inbound Home Assistant port.

Version 2.1.0 adds bounded entity discovery by entity ID or friendly name so the
agent can resolve natural-language device names without requiring manual lookup.
