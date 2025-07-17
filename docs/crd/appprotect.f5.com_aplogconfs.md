# APLogConf

**Group:** `appprotect.f5.com`  
**Version:** `v1beta1`  
**Kind:** `APLogConf`  
**Scope:** `Namespaced`

## Description

The `APLogConf` resource defines the logging configuration for NGINX App Protect. It allows you to specify the format and content of security logs, as well as filters to control which requests are logged.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `content` | `object` | Configuration object. |
| `content.escaping_characters` | `array` | List of configuration values. |
| `content.escaping_characters[].from` | `string` | String configuration value. |
| `content.escaping_characters[].to` | `string` | String configuration value. |
| `content.format` | `string` | Allowed values: `"splunk"`, `"arcsight"`, `"default"`, `"user-defined"`, `"grpc"`. |
| `content.format_string` | `string` | String configuration value. |
| `content.list_delimiter` | `string` | String configuration value. |
| `content.list_prefix` | `string` | String configuration value. |
| `content.list_suffix` | `string` | String configuration value. |
| `content.max_message_size` | `string` | String configuration value. |
| `content.max_request_size` | `string` | String configuration value. |
| `filter` | `object` | Configuration object. |
| `filter.request_type` | `string` | Allowed values: `"all"`, `"illegal"`, `"blocked"`. |
