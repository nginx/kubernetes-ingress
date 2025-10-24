# Enable Keda scale to 0 in off hours

This example is based on the official Keda [example](https://keda.sh/docs/2.18/scalers/cron/#scale-to-0-during-off-hours).

## 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller.

## 2. Deploy Keda

1. Follow the [installation](https://keda.sh/docs/2.18/deploy/) instructions to suit your deployment preference.

## 3. Apply the Keda ScaledObject

Adjust the settings to suit your requirements.  See the [ScaledObject](https://keda.sh/docs/2.18/reference/scaledobject-spec/) reference for more details

1. Apply `scaled-object.yaml`

```console
kubectl apply -f scaled-object.yaml
```

## 4. Configure deployment replicas

1. Remove the `spec.replicas` from your deployment to allow Keda to autoscale your pods.

2. Once the end time has expired, 5 minutes from then the NGINX Ingress Controller pods should scale to 0.
