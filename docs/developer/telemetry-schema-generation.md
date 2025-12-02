# Telemetry Schema Generation

This document outlines how to update the `data.avdl` schema file in `internal/telemetry`
This document also details reasons why the schema file would need to be updated.

## Updating the schema
In the root of the project, run the below Make command
```
make telemetry-schema
```

Depending on what kind of update was made, different files will be updated,
- `internal/telemetry/nicresourcecounts_attributes_generated.go`
  This file is updated if properties in NICResourceCounts are added, updated or deleted.

- `internal/telemetry/data_attributes_generated.go`
  This file is update if properties of the Data struct in the [telemetry-exporter](https://github.com/nginx/telemetry-exporter) library are added, updated or deleted.

- `internal/telemetry/data.avdl`
  This file is updated if either the NICResourceCounts or the Data struct is updated.

## Reasons to update the Schema file
1. A new data point is being collected

We may choose to collect a count of a new resource managed by the Ingress Controller.
In this case, the `NICResourceCounts` struct in `internal/telemetry/exporter.go` would be updated
```
type NICResourceCounts struct {
	// MyNewResources is the number of MyNewResources resources managed by the Ingress Controller.
	MyNewResources int64
}
```

2. An existing data point has been updated or delete

This may either be a data point under `NICResourceCounts`, or a field in the common `Data` struct in [telemetry-exporter](https://github.com/nginx/telemetry-exporter) library.
For example, we may change the name of, or delete, `MyNewResources` used in the first example.
