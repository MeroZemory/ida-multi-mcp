import socket

from ida_multi_mcp.vendor.zeromcp.mcp import (
    _IPv6HTTPServer,
    _IPv6ThreadingHTTPServer,
    _host_header_hostname,
    _http_server_class,
)


def test_ipv6_host_header_is_parsed_without_losing_identity():
    assert _host_header_hostname("[::1]:54321") == "::1"


def test_malformed_host_header_fails_closed():
    assert _host_header_hostname("[::1") is None


def test_ipv6_server_classes_use_ipv6_sockets():
    assert _http_server_class("::1", False) is _IPv6HTTPServer
    assert _http_server_class("::1", True) is _IPv6ThreadingHTTPServer
    assert _IPv6HTTPServer.address_family == socket.AF_INET6
    assert _IPv6ThreadingHTTPServer.address_family == socket.AF_INET6
