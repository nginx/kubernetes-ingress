"""Describe project settings"""

import os

BASEDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOYMENTS = f"{BASEDIR}/deployments"
HELM_CHARTS = f"{BASEDIR}/charts/nginx-ingress"
CRDS = f"{BASEDIR}/config/crd/bases"
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
TEST_DATA = f"{PROJECT_ROOT}/data"
NUM_REPLICAS = 1
DEFAULT_IMAGE = "nginx/nginx-ingress:edge"
DEFAULT_PULL_POLICY = "IfNotPresent"
DEFAULT_IC_TYPE = "nginx-ingress"
ALLOWED_IC_TYPES = ["nginx-ingress", "nginx-plus-ingress"]
DEFAULT_SERVICE = "nodeport"
ALLOWED_SERVICE_TYPES = ["nodeport", "loadbalancer"]
DEFAULT_DEPLOYMENT_TYPE = "deployment"
ALLOWED_DEPLOYMENT_TYPES = ["deployment", "daemon-set"]
# Time in seconds to ensure reconfiguration changes in cluster
RECONFIGURATION_DELAY = 3
NGINX_API_VERSION = 4

"""Settings below are test specific"""
# Determines if batch reload tests will be ran or not
BATCH_START = "False"
# Number of Ingress/VS resources to deploy based on BATCH_START value, used in test_batch_startup_times.py and test_batch_reloads.py
BATCH_RESOURCES = 1
# Threshold for batch reloads (reloads for batch requests should be at or below this number). Used in test_batch_reloads.py
BATCH_RELOAD_NUMBER = 2
# Number of namespaces to deploy to measure Pod performance, used in test_multiple_ns_perf.py
NS_COUNT = 0
# Nginx registry address to pull waf components from
NGX_REG = "gcr.io/f5-gcs-7899-ptg-ingrss-ctlr"
# WAF component version to pull from above registry
WAF_V5_VERSION = "5.5.0"
