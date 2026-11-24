# How to generate the gRPC files

The files here are generated using `helloworld.proto` from the grpc
[repo](https://github.com/grpc/grpc-go/tree/master/examples/helloworld/helloworld).

The protobuf compiler (`grpcio-tools`) is not part of `tests/requirements.in`, so install it
into the test venv (`make setup-venv`) first. Use the same version as the locked `grpcio`,
otherwise the generated stubs may refuse to load against it.

To update the files run the following commands from this directory:

```console
source ../../venv/bin/activate
pip install "grpcio-tools==$(sed -n 's/^grpcio==\([^ ]*\).*/\1/p' ../../requirements.txt)"
python3 -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. helloworld.proto
```
