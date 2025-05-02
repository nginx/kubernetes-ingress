package telemetry

/*
This is a generated file. DO NOT EDIT.
*/

import (
	"go.opentelemetry.io/otel/attribute"

	ngxTelemetry "github.com/nginx/telemetry-exporter/pkg/telemetry"
)

func (d *Data) Attributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue
	attrs = append(attrs, attribute.String("dataType", "nic-product-telemetry"))
	attrs = append(attrs, d.Data.Attributes()...)
	attrs = append(attrs, d.NICResourceCounts.Attributes()...)

	return attrs
}

var _ ngxTelemetry.Exportable = (*Data)(nil)
