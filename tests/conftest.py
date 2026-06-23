"""Describe overall framework configuration."""

import os

import pytest
from kubernetes.config.kube_config import KUBE_CONFIG_DEFAULT_LOCATION
from settings import (
    BATCH_RELOAD_NUMBER,
    BATCH_RESOURCES,
    BATCH_START,
    DEFAULT_DEPLOYMENT_TYPE,
    DEFAULT_IC_TYPE,
    DEFAULT_IMAGE,
    DEFAULT_PULL_POLICY,
    DEFAULT_SERVICE,
    NS_COUNT,
    NUM_REPLICAS,
)
from suite.utils.resources_utils import (
    are_all_pods_in_ready_state,
    get_first_pod_name,
    wait_before_test,
)


def pytest_addoption(parser) -> None:
    """Get cli-arguments.

    :param parser: pytest parser
    :return:
    """
    parser.addoption(
        "--context",
        action="store",
        default="",
        help="The context to use in the kubeconfig file.",
    )
    parser.addoption(
        "--image",
        action="store",
        default=DEFAULT_IMAGE,
        help="The Ingress Controller image.",
    )
    parser.addoption(
        "--image-pull-policy",
        action="store",
        default=DEFAULT_PULL_POLICY,
        help="The pull policy of the Ingress Controller image.",
    )
    parser.addoption(
        "--deployment-type",
        action="store",
        default=DEFAULT_DEPLOYMENT_TYPE,
        help="The type of the IC deployment: deployment, daemon-set, or stateful-set.",
    )
    parser.addoption(
        "--ic-type",
        action="store",
        default=DEFAULT_IC_TYPE,
        help="The type of the Ingress Controller: nginx-ingress or nginx-plus-ingress.",
    )
    parser.addoption(
        "--plus-jwt",
        action="store",
        help="The plus jwt for the Ingress Controller image.",
        default=os.environ.get("PLUS_JWT"),
    )
    parser.addoption(
        "--service",
        action="store",
        default=DEFAULT_SERVICE,
        help="The type of the Ingress Controller service: nodeport or loadbalancer.",
    )
    parser.addoption(
        "--replicas",
        action="store",
        default=NUM_REPLICAS,
        help="Number of replica pods for type deployment",
    )
    parser.addoption(
        "--node-ip",
        action="store",
        help="The public IP of a cluster node. Not required if you use the loadbalancer service (see --service argument).",
    )
    parser.addoption(
        "--kubeconfig",
        action="store",
        default=os.path.expanduser(KUBE_CONFIG_DEFAULT_LOCATION),
        help="An absolute path to a kubeconfig file.",
    )
    parser.addoption(
        "--show-ic-logs",
        action="store",
        default="no",
        help="Show IC logs in stdout on test failure",
    )
    parser.addoption(
        "--skip-fixture-teardown",
        action="store",
        default="no",
        help="Skips teardown of test fixtures for debugging purposes",
    )
    parser.addoption(
        "--batch-start",
        action="store",
        default=BATCH_START,
        help="Run tests for pods restarts with multiple resources deployed (Ingress/VS): True/False",
    )
    parser.addoption(
        "--batch-resources",
        action="store",
        default=BATCH_RESOURCES,
        help="Number of VS/Ingress resources to deploy",
    )
    parser.addoption(
        "--batch-reload-number",
        action="store",
        default=BATCH_RELOAD_NUMBER,
        help="Number of reloads expected for batch reload test",
    )
    parser.addoption(
        "--ns-count",
        action="store",
        default=NS_COUNT,
        help="Number for namespaces to deploy for use in test_multiple_ns_perf.py",
    )
    parser.addoption(
        "--num",
        action="store",
        default="1",
        help="Number of resources to deploy for upgrade tests",
    )
    parser.addoption(
        "--docker-registry-user",
        action="store",
        default="",
        help="Docker registry username",
    )
    parser.addoption(
        "--docker-registry-token",
        action="store",
        default="",
        help="Docker registry token",
    )


# import fixtures into pytest global namespace
pytest_plugins = [
    "suite.fixtures.fixtures",
    "suite.fixtures.ic_fixtures",
    "suite.fixtures.custom_resource_fixtures",
    "suite.utils.external_auth_utils",
]


def pytest_configure(config):
    if config.getoption("--ic-type") == "nginx-plus-ingress" and (
        config.getoption("--plus-jwt") == "" or config.getoption("--plus-jwt") is None
    ):
        pytest.exit("Please provide the plus jwt for the Nginx Ingress Controller")


def pytest_collection_modifyitems(config, items) -> None:
    """
    Skip tests marked with '@pytest.mark.skip_for_nginx_oss' for Nginx OSS runs.
    Skip tests marked with '@pytest.mark.appprotect' for non AP images.
    Skip tests marked with '@pytest.mark.dos' for non DOS images

    :param config: pytest config
    :param items: pytest collected test-items
    :return:
    """
    if config.getoption("--ic-type") == "nginx-ingress":
        skip_for_nginx_oss = pytest.mark.skip(reason="Skip a test for Nginx OSS")
        for item in items:
            if "skip_for_nginx_oss" in item.keywords:
                item.add_marker(skip_for_nginx_oss)
    if config.getoption("--ic-type") == "nginx-plus-ingress":
        skip_for_nginx_plus = pytest.mark.skip(reason="Skip a test for Nginx Plus")
        for item in items:
            if "skip_for_nginx_plus" in item.keywords:
                item.add_marker(skip_for_nginx_plus)
    if config.getoption("--service") == "loadbalancer":
        skip_for_loadbalancer = pytest.mark.skip(reason="Skip a test for loadbalancer service")
        for item in items:
            if "skip_for_loadbalancer" in item.keywords:
                item.add_marker(skip_for_loadbalancer)
    if "-nap" not in config.getoption("--image"):
        appprotect = pytest.mark.skip(reason="Skip AppProtect WAF v4 test in non-AP WAF v4 image")
        for item in items:
            if "appprotect" in item.keywords:
                item.add_marker(appprotect)
    if "-nap-v5" not in config.getoption("--image"):
        appprotect_v5 = pytest.mark.skip(reason="Skip AppProtect WAF v5 test in non-AP WAF v5 image")
        for item in items:
            if "appprotect_waf_v5" in item.keywords:
                item.add_marker(appprotect_v5)
    if "-dos" not in config.getoption("--image"):
        dos = pytest.mark.skip(reason="Skip DOS test in non-DOS image")
        for item in items:
            if "dos" in item.keywords:
                item.add_marker(dos)
    if str(config.getoption("--batch-start")) != "True":
        batch_start = pytest.mark.skip(reason="Skipping pod restart test with multiple resources")
        for item in items:
            if "batch_start" in item.keywords:
                item.add_marker(batch_start)

    if int(config.getoption("--ns-count")) <= 0:
        multi_ns = pytest.mark.skip(reason="Skipping watch-namespaces perf. tests")
        for item in items:
            if "multi_ns" in item.keywords:
                item.add_marker(multi_ns)

    # Reorder items to group tests by Ingress Controller fixture profile so the
    # session-scoped IC pool can reuse the same IC deployment across as many
    # consecutive test classes as possible. Within each profile group the
    # original collection order is preserved (Python's sort is stable).
    _sort_items_by_ic_profile(items)


# Fixtures that share the session-scoped ic_pool. Test classes using any of
# these can reuse the same IC deployment when their extra_args match.
_POOL_FIXTURES = frozenset(
    {
        "crd_ingress_controller",
        "crd_ingress_controller_with_ap",
        "crd_ingress_controller_with_dos",
        "crd_ingress_controller_with_ed",
    }
)

# Fixtures that create their own IC deployment outside the pool. Tests using
# these force the pool to be torn down, so we group them last.
_INLINE_IC_FIXTURES = frozenset(
    {
        "ingress_controller",
        "crd_ingress_controller_with_waf_v5",
    }
)


def _ic_profile_key(item) -> tuple:
    """Return a sort key that groups items by IC fixture profile.

    Order:
        0. Tests that do not require an IC at all (run first).
        1. Tests using a pool-backed CRD IC fixture, sub-sorted by the
           pool config key (extra_args) so consecutive classes can reuse the
           running IC.
        2. Tests using fixtures that create an IC outside the pool
           (forces a pool teardown).

    Returned tuple is (group_priority, pool_subkey, fixture_name).
    """
    fixturenames = set(getattr(item, "fixturenames", ()))

    pool_fixture = next((f for f in _POOL_FIXTURES if f in fixturenames), None)
    if pool_fixture is not None:
        # Try to extract extra_args from the parametrized fixture value so
        # classes with matching args run consecutively (maximum pool reuse).
        extra_args_key: tuple = ()
        callspec = getattr(item, "callspec", None)
        if callspec is not None:
            params = getattr(callspec, "params", {}) or {}
            param_value = params.get(pool_fixture)
            if isinstance(param_value, dict):
                extra_args = param_value.get("extra_args") or []
                if isinstance(extra_args, (list, tuple)):
                    extra_args_key = tuple(sorted(str(a) for a in extra_args))
        return (1, extra_args_key, pool_fixture)

    inline_fixture = next((f for f in _INLINE_IC_FIXTURES if f in fixturenames), None)
    if inline_fixture is not None:
        return (2, (), inline_fixture)

    return (0, (), "")


def _sort_items_by_ic_profile(items) -> None:
    """In-place stable sort of test items by IC fixture profile."""
    items.sort(key=_ic_profile_key)


def pytest_runtest_logstart(nodeid, location) -> None:
    """
    Ensure each test's captured output starts on a new line.

    Pytest writes the test nodeid (e.g. ``suite/test_foo.py::TestBar::test_baz``)
    to the terminal without a trailing newline at the start of each test. When
    ``-s`` is used, any prints from fixtures or setup are then appended to that
    same line. Emitting a newline here puts subsequent output on its own line.
    """
    print()


def pytest_runtest_teardown(item, nextitem) -> None:
    """
    Ensure teardown output starts on a new line.

    Pytest writes the call-phase status (e.g. ``PASSED``) without a trailing
    newline, so prints from teardown fixtures would otherwise appear directly
    after it (e.g. ``PASSEDClean up the Application:``).
    """
    print()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item) -> None:
    """
    Print out IC Pod logs on test failure.

    Only look at actual failing test calls, not setup/teardown.
    Only show the logs if commandline argument `--show-ic-logs` is set to 'yes'

    :param item:
    :return:
    """
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # we only look at actual failing test calls, not setup/teardown
    if rep.when == "call" and rep.failed and item.config.getoption("--show-ic-logs") == "yes":
        pod_namespace = item.funcargs["ingress_controller_prerequisites"].namespace
        pod_name = get_first_pod_name(item.funcargs["kube_apis"].v1, pod_namespace)
        print("\n===================== IC Logs Start =====================")
        count = 0
        while (not are_all_pods_in_ready_state(item.funcargs["kube_apis"].v1, pod_namespace)) and count < 10:
            count += 1
            wait_before_test()
        log_output = item.funcargs["kube_apis"].v1.read_namespaced_pod_log(pod_name, pod_namespace)
        if isinstance(log_output, bytes):
            log_output = log_output.decode("utf-8", errors="replace")
        for line in log_output.splitlines():
            print(line)
        print("\n===================== IC Logs End =====================")

    if rep.when == "call" and item.config.getoption("--skip-fixture-teardown") == "yes":
        print("\n===================== WARNING =====================")
        print("Make sure to remove resources from this test run manually using kubectl utility\n")
