# APDosLogConf

**Group:** `appprotectdos.f5.com`  
**Version:** `v1beta1`  
**Kind:** `APDosLogConf`  
**Scope:** `Namespaced`

## Description

The `APDosLogConf` resource defines the logging configuration for the NGINX App Protect DoS module. It allows you to specify the format and content of security logs, as well as filters to control which events are logged.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `content` | `object` | Configuration object. |
| `content.format` | `string` | Allowed values: `"splunk"`, `"arcsight"`, `"user-defined"`. |
| `content.format_string` | `string` | String configuration value. |
| `content.max_message_size` | `string` | String configuration value. |
| `filter` | `object` | Configuration object. |
| `filter.attack-signatures` | `string` | String configuration value. |
| `filter.bad-actors` | `string` | String configuration value. |
| `filter.traffic-mitigation-stats` | `string` | Allowed values: `"none"`, `"all"`. |
