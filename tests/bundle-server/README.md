Mock Bundle Server
---

Simple NGINX server to serve files.

Created to serve App Protect policy and log configuration bundles as `.tgz` files.

**Note*: This server is not intended for production use and should only be used for testing purposes.

cd into the `bundle-server` directory before running `docker build`.

### Usage

1. `cd tests/bundle-server`

2. Build the server image:

```shell
docker build -t bundle-server:latest .
```

3. Run the server, mount the 'bundles' directory:

```shell
# Listening on port 8080, serving files from the '/www/bundles' directory
docker run --rm -p 8080:80 -v $(pwd)/bundles:/www/bundles --name bundle-server local/bundle-server:latest
```

4. Access the bundles at `http://localhost:8080/bundles/<bundle_name>.tgz`
Example:

```shell
curl -O http://localhost:8080/bundles/policy.tgz
curl -O http://localhost:8080/bundles/logs.tgz
```

---
Additionally we provide an example deployment of the bundle server in Kubernetes, which can be used to serve bundles
within a cluster. The `deployment.yaml` file defines a Deployment and Service for the bundle server.
Adjust image names and ports as needed.
