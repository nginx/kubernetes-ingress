# Tests

The project includes automated tests for testing the NGINX Ingress Controller in a Kubernetes cluster. The tests are written in Python 3 and use the pytest framework with additional tools like Playwright for browser automation.

This documentation covers how to run tests against Minikube and Kind clusters, though the tests can be run against any Kubernetes cluster. See the [Configuring the Tests](#configuring-the-tests) section for various configuration options.

## Running Tests in Minikube

### Prerequisites

- [Minikube](https://minikube.sigs.k8s.io/docs/)
- Python 3.10+ or Docker

#### Step 1 - Create a Minikube Cluster

```bash
minikube start
```

#### Step 2 - Run the Tests

**Note**: If you have the Ingress Controller already deployed in the cluster, please uninstall it first, ensuring you remove its namespace and RBAC resources.

Run the tests using one of the following methods:

- **Use Python3 virtual environment (recommended):**

    Create and activate a virtual environment:

    ```bash
    cd tests
    make setup-venv
    pytest --node-ip=$(minikube ip)
    ```

- **Use local Python3 installation:**

    ```bash
    cd tests
    pip install -r requirements.txt
    pytest --node-ip=$(minikube ip)
    ```

- **Use Docker:**

    ```bash
    cd tests
    make build
    make run-tests NODE_IP=$(minikube ip)
    ```

The tests will use the Ingress Controller for NGINX with the default *nginx/nginx-ingress:edge* image. See the section
below to learn how to configure the tests including the image and the type of NGINX -- NGINX or NGINX Plus.

## Running Tests in Kind

### Prerequisites

- [Kind](https://kind.sigs.k8s.io/)
- Docker

**Note**: All commands in the steps below are executed from the `tests` directory.

List available make commands:

```bash
make help
```

This will show you all available targets including:

- `build` - Build the test container image
- `run-tests` - Run tests in Docker
- `run-tests-in-kind` - Run tests in Kind cluster
- `create-kind-cluster` - Create a Kind cluster
- `delete-kind-cluster` - Delete a Kind cluster

#### Step 1 - Create a Kind Cluster

```bash
make create-kind-cluster
```

#### Step 2 - Run the Tests

**Note**: If you have the Ingress Controller already deployed in the cluster, please uninstall it first, ensuring you remove its namespace and RBAC resources.

Run the tests in Docker:

```bash
make build
make run-tests-in-kind
```

The tests will use the NGINX Ingress Controller with the default `nginx/nginx-ingress:edge` image. See the [Configuring the Tests](#configuring-the-tests) section to learn how to configure different images and NGINX types (OSS vs Plus).

## Additional Make Targets

The test suite includes several additional make targets for cluster management and cleanup:


- `make create-mini-cluster` - Create a Minikube K8S cluster
- `make delete-mini-cluster` - Delete a Minikube K8S cluster  
- `make run-tests-in-minikube` - Run tests in Minikube
- `make mini-image-load` - Load the image into the Minikube K8S cluster
- `make image-load` - Load the image into the Kind K8S cluster
- `make mini-image-load` - Load the image into the Minikube K8S cluster
- `make setup-venv` - Create Python virtual environment with all dependencies
- `make clean-venv` - Remove Python virtual environment
- `make run-local-tests` - Run tests using local Python environment
- `make test-lint` - Run Python linting tools (isort, black)

## Configuring the Tests

The table below shows various configuration options for the tests. If you use Python 3 to run the tests locally, use the command-line arguments. If you use Docker, use the [Makefile](Makefile) variables.

| Command-line Argument | Makefile Variable | Description | Default |
| :----------------------- | :------------ | :------------ | :----------------------- |
| `--context` | `CONTEXT`, not supported by `run-tests-in-kind` target. | The context to use in the kubeconfig file. | `""` |
| `--image` | `BUILD_IMAGE` | The Ingress Controller image. | `nginx/nginx-ingress:edge` |
| `--image-pull-policy` | `PULL_POLICY` | The pull policy of the Ingress Controller image. | `IfNotPresent` |
| `--deployment-type` | `DEPLOYMENT_TYPE` | The type of the IC deployment: deployment, daemon-set or stateful-set. | `deployment` |
| `--ic-type` | `IC_TYPE` | The type of the Ingress Controller: nginx-ingress or nginx-plus-ingress. | `nginx-ingress` |
| `--service` | `SERVICE`, not supported by `run-tests-in-kind` target.  | The type of the Ingress Controller service: nodeport or loadbalancer. | `nodeport` |
| `--node-ip` | `NODE_IP`, not supported by `run-tests-in-kind` target.  | The public IP of a cluster node. Not required if you use the loadbalancer service (see --service argument). | `""` |
| `--kubeconfig` | `N/A` | An absolute path to a kubeconfig file. | `~/.kube/config` or the value of the `KUBECONFIG` env variable |
| `N/A` | `KUBE_CONFIG_FOLDER`, not supported by `run-tests-in-kind` target. | A path to a folder with a kubeconfig file. | `~/.kube/` |
| `--show-ic-logs` | `SHOW_IC_LOGS` | A flag to control accumulating IC logs in stdout. | `no` |
| `--skip-fixture-teardown` | `N/A` | A flag to skip test fixture teardown for debugging. | `no` |
| `--plus-jwt` | `PLUS_JWT` | JWT token for NGINX Plus image authentication. | `""` |
| `N/A` | `PYTEST_ARGS` | Any additional pytest command-line arguments (i.e `-m "smoke"`) | `""` |

If you would like to use an IDE (such as PyCharm) to run the tests, use the [pyproject.toml](../pyproject.toml) file to view pytest configuration and markers.

Tests are marked with custom markers that allow you to logically split all tests into smaller groups. The full list can be found in the [pyproject.toml](../pyproject.toml) file or via command line:

```bash
pytest --markers
```

## Test Containers

The source code for the tests containers used in some tests, for example the
[transport-server-tcp-load-balance](./data/transport-server-tcp-load-balance/standard/service_deployment.yaml) is
located at [kic-test-containers](https://github.com/nginx/kic-test-containers).

## Test Structure

The test suite is organized as follows:

- `suite/` - Main test files organized by functionality
- `data/` - Test data and configuration files
- `ci-files/` - Continuous integration configuration
- `conftest.py` - pytest configuration and fixtures
- `requirements.txt` - Python dependencies with hash verification
- `Makefile` - Build and test automation

### Test Dependencies

The tests require several Python packages including:

- `pytest` - Testing framework
- `kubernetes` - Kubernetes Python client
- `requests` - HTTP library
- `playwright` - Browser automation for UI tests etc.

You can find rest of the dependencies in `requirements.txt`
All dependencies are pinned with hashes.
