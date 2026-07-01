[![Continuous Integration](https://github.com/nginx/nginx-ingress-helm-operator/workflows/Continuous%20Integration/badge.svg)](https://github.com/nginx/nginx-ingress-helm-operator/actions)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/nginx/nginx-ingress-helm-operator/badge)](https://api.securityscorecards.dev/projects/github.com/nginx/nginx-ingress-helm-operator)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
![Commercial Support](https://badgen.net/badge/support/commercial/green?icon=awesome)

# NGINX Ingress Operator

The NGINX Ingress Operator is a Kubernetes/OpenShift component which deploys and manages one or more [NGINX/NGINX Plus Ingress Controllers](https://github.com/nginx/kubernetes-ingress) which in turn handle Ingress traffic for applications running in a cluster.

Learn more about operators in the [Kubernetes Documentation](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

To install a specific version of the NGINX Ingress Controller with the operator, a specific version of the NGINX Ingress Operator is required.

Up until version 0.5.1, this Operator was Go based. Version 1.0.0 marks an incompatible upgrade as this release switched the Operator to being Helm-based, built from the [NGINX Ingress Controller Helm chart](http://helm.nginx.com/#nginx-ingress-controller). The configuration for the Helm chart can be seen in the [NGINX Ingress Controller documentation](https://docs.nginx.com/nginx-ingress-controller/install/helm#configuration).

The following table shows the relation between the versions of the two projects:

| NGINX Ingress Controller | NGINX Ingress Operator |
| ------------------------ | ---------------------- |
| 5.5.x                    | 3.6.2                  |
| 5.4.x                    | 3.5.4                  |
| 5.3.x                    | 3.4.4                  |
| 5.2.x                    | 3.3.1                  |
| 5.1.x                    | 3.2.3                  |
| 5.0.x                    | 3.1.0                  |
| 4.0.x                    | 3.0.1                  |
| 3.7.x                    | 2.4.2                  |
| 3.6.x                    | 2.3.2                  |
| 3.5.x                    | 2.2.2                  |
| 3.4.x                    | 2.1.2                  |
| 3.3.x                    | 2.0.2                  |
| 3.2.x                    | 1.5.2                  |
| 3.1.x                    | 1.4.2                  |
| 3.0.x                    | 1.3.1                  |
| 2.4.x                    | 1.2.1                  |
| 2.3.x                    | 1.1.0                  |
| 2.2.x                    | 1.0.0                  |
| 2.1.x                    | 0.5.1                  |
| 2.0.x                    | 0.4.0                  |
| 1.12.x                   | 0.3.0                  |
| 1.11.x                   | 0.2.0                  |
| 1.10.x                   | 0.1.0                  |
| 1.9.x                    | 0.0.7                  |
| 1.8.x                    | 0.0.6                  |
| 1.7.x                    | 0.0.4                  |
| < 1.7.0                  | N/A                    |

Note: The NGINX Ingress Operator works only for NGINX Ingress Controller versions after `1.7.0`.

## Getting Started

1. Install the NGINX Ingress Operator. See [docs](./docs/installation.md).
   <br> NOTE: To use TransportServers as part of your NGINX Ingress Controller configuration, a GlobalConfiguration resource must be created _before_ starting the Operator - [see the notes](./examples/deployment-oss-min/README.md#TransportServers)
2. Creating the default-server-secret.yaml is optional and it is recommended that users provide their own certificate. An example yaml for this can be found in the [examples folder](https://github.com/nginx/nginx-ingress-helm-operator/blob/main/examples/default-server-secret.yaml)
3. (If using OpenShift) Create the scc resource on the cluster by applying the scc.yaml file found in the `resources` folder of this repo:

   ```shell
   kubectl apply -f https://raw.githubusercontent.com/nginx/nginx-ingress-helm-operator/main/resources/scc.yaml
   ```

4. Deploy a new NGINX Ingress Controller using the [NginxIngress](./config/samples/charts_v1alpha1_nginxingress.yaml) Custom Resource:
   - Use the name of the default server secret created above for `controller.defaultTLS.secret` field (needs to be in the form `namespace/name`)
   - If using NGINX Plus:
     - Set the `controller.nginxPlus` to true
     - Set the `controller.image.repository` and `controller.image.tag` to the appropriate values
     - Set the `controller.serviceAccount.imagePullSecretName` if applicable
   - For full configuration details see the Helm documentation [here](https://docs.nginx.com/nginx-ingress-controller/install/helm/#configuration).

## Notes: Multiple NIC Deployments

- Please see [the NGINX Ingress Controller documentation](https://docs.nginx.com/nginx-ingress-controller/install/multiple-controllers/) for general information on running multiple NGINX Ingress Controllers in your cluster.
- To run multiple NIC instances deployed by the NGINX Ingress Operator in your cluster in the same namespace, `rbac.create` should be set to `false`, and the ServiceAccount and ClusterRoleBinding need to be created independently of the deployments. Please note that `controller.serviceAccount.imagePullSecretName` will also be ignored in this configuration, and will need to be configured as part of the independent ServiceAccount creation.
- The ClusterRoleBinding needs to configured to bind to the `nginx-ingress-operator-nginx-ingress-admin` ClusterRole.
- See [RBAC example spec](./resources/rbac-example.yaml) for an example ServiceAccount and ClusterRoleBinding manifest.
- To run multiple NIC instances deployed by the NGINX Ingress Operator in your cluster in any namespace but sharing an IngressClass, `controller.ingressClass.name` should be set to an empty string and the IngressClass resource needs to be created independently of the deployments.Please note that `controller.ingressClass.setAsDefaultIngress` will also be ignored in this configuration, and will need to be configured as part of the independent IngressClass creation.
- See [IngressClass example spec](./resources/ingress-class.yaml) for an example IngressClass manifest.

## Upgrades

See [upgrade docs](./docs/upgrades.md)

## NGINX Ingress Operator Releases

We publish NGINX Ingress Operator releases on GitHub. See our [releases page](https://github.com/nginx/nginx-ingress-helm-operator/releases).

The latest stable release is [3.6.2](https://github.com/nginx/nginx-ingress-helm-operator/releases/tag/v3.6.2). For production use, we recommend that you choose the latest stable release.

## Development

It is possible to run the operator in your local machine. This is useful for testing or during development.

### Run Operator locally

1. Have access to a Kubernetes/OpenShift cluster.
2. Apply the IC CRD:

   ```shell
    make install
   ```

3. Run `make run`.

The operator will run in your local machine but will be communicating with the cluster.

## Contributing

If you'd like to contribute to the project, please read our [Contributing](./CONTRIBUTING.md) guide.
