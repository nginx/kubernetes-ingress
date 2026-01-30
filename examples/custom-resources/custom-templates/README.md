# Custom Templates

The Ingress Controller uses a template to generate NGINX configuration for VirtualServer resources. You can customize
the template and apply it via the ConfigMap. See the [combined custom
templates](../../shared-examples/custom-templates/README.md) example, which shows how to customize the template
for the VirtualServer resource as well as the other templates used by the Ingress Controller.
