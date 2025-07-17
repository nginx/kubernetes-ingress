# DNSEndpoint

**Group:** `externaldns.nginx.org`  
**Version:** `v1`  
**Kind:** `DNSEndpoint`  
**Scope:** `Namespaced`

## Description

The `DNSEndpoint` resource is used to manage DNS records for services exposed through NGINX Ingress Controller. It is typically used in conjunction with ExternalDNS to automatically create and update DNS records.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `endpoints` | `array` | List of configuration values. |
| `endpoints[].dnsName` | `string` | The hostname for the DNS record |
| `endpoints[].labels` | `object` | Labels stores labels defined for the Endpoint |
| `endpoints[].providerSpecific` | `array` | ProviderSpecific stores provider specific config |
| `endpoints[].providerSpecific[].name` | `string` | Name of the property |
| `endpoints[].providerSpecific[].value` | `string` | Value of the property |
| `endpoints[].recordTTL` | `integer` | TTL for the record |
| `endpoints[].recordType` | `string` | RecordType type of record, e.g. CNAME, A, SRV, TXT, MX |
| `endpoints[].targets` | `array[string]` | The targets the DNS service points to |
