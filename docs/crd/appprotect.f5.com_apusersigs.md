# APUserSig

**Group:** `appprotect.f5.com`  
**Version:** `v1beta1`  
**Kind:** `APUserSig`  
**Scope:** `Namespaced`

## Description

The `APUserSig` resource defines a custom user-defined signature for NGINX App Protect. It allows you to create your own signatures to detect specific attack patterns or vulnerabilities.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `properties` | `string` | String configuration value. |
| `signatures` | `array` | List of configuration values. |
| `signatures[].accuracy` | `string` | Allowed values: `"high"`, `"medium"`, `"low"`. |
| `signatures[].attackType` | `object` | Configuration object. |
| `signatures[].attackType.name` | `string` | String configuration value. |
| `signatures[].description` | `string` | String configuration value. |
| `signatures[].name` | `string` | String configuration value. |
| `signatures[].references` | `object` | Configuration object. |
| `signatures[].references.type` | `string` | Allowed values: `"bugtraq"`, `"cve"`, `"nessus"`, `"url"`. |
| `signatures[].references.value` | `string` | String configuration value. |
| `signatures[].risk` | `string` | Allowed values: `"high"`, `"medium"`, `"low"`. |
| `signatures[].rule` | `string` | String configuration value. |
| `signatures[].signatureType` | `string` | Allowed values: `"request"`, `"response"`. |
| `signatures[].systems` | `array` | List of configuration values. |
| `signatures[].systems[].name` | `string` | String configuration value. |
| `softwareVersion` | `string` | String configuration value. |
| `tag` | `string` | String configuration value. |
