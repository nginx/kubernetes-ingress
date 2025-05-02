"""Describe methods to handle ssl connections."""

import socket
import ssl

import OpenSSL
import requests
from requests.adapters import HTTPAdapter


def get_certificate(ip_address, host, port, timeout=10) -> str:
    """
    Get tls certificate.
    :param ip_address:
    :param host:
    :param port:
    :param timeout:
    :return: str
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ip_address = ip_address.strip("[]")
    conn = socket.create_connection((ip_address, port))
    server_hostname = host if ssl.HAS_SNI else None
    sock = context.wrap_socket(conn, server_hostname=server_hostname)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


def get_server_certificate_subject(ip_address, host, port=443) -> dict:
    """
    Get tls certificate subject object.
    :param port: default is 443
    :param ip_address:
    :param host:
    :return: dict
    """
    certificate = get_certificate(ip_address, host, port)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    return dict(x509.get_subject().get_components())


class SNIAdapter(HTTPAdapter):
    """
    An HTTP adapter for the requests library that ensures that the SNI of a TLS connection is set to the custom host
    header.
    Usage::
      >>> s = requests.Session()
      >>> s.mount("https://", SNIAdapter())
      >>> resp = s.get("https://127.0.0.1:8443", headers={"host": "webapp.example.com"}, verify=False)
    """

    def send(self, request, **kwargs):
        # overrides the SNI to the value of the host header
        # See urllib3.connection.HTTPSConnection.connect
        self.poolmanager.connection_pool_kw["server_hostname"] = request.headers["host"]
        return super().send(request, **kwargs)


def create_sni_session():
    """
    Creates a session that will ensure that the SNI of TLS connection is set to the custom host header.
    :return: requests.sessions.Session
    """
    s = requests.Session()
    s.mount("https://", SNIAdapter())
    return s
