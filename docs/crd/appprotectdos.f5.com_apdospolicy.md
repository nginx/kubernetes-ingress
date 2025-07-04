# APDosPolicy

**Group:** `appprotectdos.f5.com`  
**Version:** `v1beta1`  
**Kind:** `APDosPolicy`  
**Scope:** `Namespaced`

## Description

The `APDosPolicy` resource defines a security policy for the NGINX App Protect Denial of Service (DoS) module. It allows you to configure various mitigation strategies to protect your applications from DoS attacks.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `automation_tools_detection` | `string` | Allowed values: `"on"`, `"off"`. |
| `bad_actors` | `string` | Allowed values: `"on"`, `"off"`. |
| `mitigation_mode` | `string` | Allowed values: `"standard"`, `"conservative"`, `"none"`. |
| `signatures` | `string` | Allowed values: `"on"`, `"off"`. |
| `tls_fingerprint` | `string` | Allowed values: `"on"`, `"off"`. |
