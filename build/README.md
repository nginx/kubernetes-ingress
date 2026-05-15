# NGINX Ingress Controller

For instructions, read the [Build NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/install/build) documentation.

The Docker image build now uses `docker buildx bake` with `docker-bake.hcl` and split Dockerfiles under `build/Dockerfile.*`.
The legacy `build/Dockerfile` remains as a fallback during the migration.
