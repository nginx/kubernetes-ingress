import io
import logging
import time

import pytest
import yaml
from settings import HELM_CHARTS
from suite.utils.resources_utils import get_first_pod_name, wait_before_test, wait_until_all_pods_are_ready


@pytest.mark.ingresses
@pytest.mark.smoke
class TestBuildVersion:
    def test_build_version(self, ingress_controller, kube_apis, ingress_controller_prerequisites):
        """
        Test Version tag of build i.e. 'Version=<VERSION>' is same as the version in the chart.yaml file
        """
        with open(f"{HELM_CHARTS}/Chart.yaml") as f:
            chart = yaml.safe_load(f)
            ic_ver = chart["appVersion"]
            print(f"NIC version from chart: {ic_ver}")
        _info = self.send_build_info(kube_apis, ingress_controller_prerequisites)
        count = 0
        while "Version=" not in _info and count < 5:
            _info = self.send_build_info(kube_apis, ingress_controller_prerequisites)
            count += 1
            time.sleep(1)
        _version = _info[_info.find("Version=") + len("Version=") : _info.rfind("Commit=")]
        logging.info(_version)
        print(f"Version from pod logs: {_version}")
        assert _version != " "
        assert ic_ver in _version

    def send_build_info(self, kube_apis, ingress_controller_prerequisites) -> str:
        """
        Helper function to get pod logs
        """
        retry = 0
        ready = False
        pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, ingress_controller_prerequisites.namespace)
        while not ready:
            wait_before_test()
            try:
                api_response = kube_apis.v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=ingress_controller_prerequisites.namespace,
                    limit_bytes=200,
                )
                logging.info(api_response)
                ready = True

            except Exception as ex:
                if retry < 10:
                    retry += 1
                    print(f"Retry# {retry}")
                else:
                    logging.exception(ex)
                    raise ex

        br = io.StringIO(api_response)
        _log = br.readline().strip()
        try:
            _info = _log[_log.find("Version") :].strip()
            print(f"Version and GitCommit info: {_info}")
            logging.info(f"Version and GitCommit info: {_info}")
        except Exception:
            logging.exception(f"Tag labels not found")

        return _info
