# Manual installation

This will deploy the operator in the `nginx-ingress-operator-system` namespace.

1. Deploy the Operator and associated resources:

   1. Clone the `nginx-ingress-operator` repo:

   ```shell
   git clone https://github.com/nginx/nginx-ingress-helm-operator/ --branch v3.6.2
   cd nginx-ingress-helm-operator/
   ```

   1. To deploy the Operator and associated resources to all environments, run:

   ```shell
   make deploy IMG=nginx/nginx-ingress-operator:3.6.2
   ```

2. Check that the Operator is running:

   ```shell
   kubectl get deployments -n nginx-ingress-operator-system

   NAME                                        READY   UP-TO-DATE   AVAILABLE   AGE
   nginx-ingress-operator-controller-manager   1/1     1            1           15s
   ```

3. `OpenShift` Additional steps:

In order to deploy NGINX Ingress Controller instances into OpenShift environments, a new SCC is required to be created on the cluster which will be used to bind the specific required capabilities to the NGINX Ingress service account(s). To do so for NIC deployments, please run the following command (assuming you are logged in with administrator access to the cluster):

`kubectl apply -f https://raw.githubusercontent.com/nginx/nginx-ingress-helm-operator/v3.6.2/resources/scc.yaml`

Alternatively, to create an SCC for NIC daemonsets, please run this command:

`kubectl apply -f https://raw.githubusercontent.com/nginx/nginx-ingress-helm-operator/v3.6.2/resources/scc-daemonset.yaml`

You can now deploy the NGINX Ingress Controller instances.

**Note: If you're upgrading your operator installation to a later release, navigate [here](../helm-charts/nginx-ingress/) and run `kubectl apply -f crds/` or `oc apply -f crds/` as a prerequisite**

## Private Registry

You can use the operator (including the kube-rbac-proxy) images from your own private registry.

1. Tag the images for your private registry

   ```shell
   docker tag quay.io/nginx/nginx-ingress-operator:3.6.2 <my-private-registry>/nginx-ingress-operator:3.6.2
   docker tag quay.io/brancz/kube-rbac-proxy:v0.18.0 <my-private-registry>/kube-rbac-proxy:v0.18.0
   ```

2. Push the image to your private registry

   ```shell
   docker push <my-private-registry>/nginx-ingress-operator:3.6.2
   docker push <my-private-registry>/kube-rbac-proxy:v0.18.0
   ```

3. Follow step 1 above but in step 1.2 you can run

   ```shell
   make deploy IMG=<my-private-registry>/nginx-ingress-operator:3.6.2 KRP_IMAGE_BASE=<my-private-registry>/kube-rbac-proxy
   ```

   **Note: If you need to use a different `kube-rbac-proxy` version than the default, use the `KRP_IMAGE_TAG` variable**  

   **Note: To use an image pull secret, you can specify the `IMAGE_PULL_SECRET_NAME` variable, eg `IMAGE_PULL_SECRET_NAME=regcred`**
