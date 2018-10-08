# Trickuri

Manual tests for URL Spoofing scenarios

This tool is designed to allow testing of applications' display of URLs.

## Background

URIs are often the only source of identity information available when making
security decisions in a web browser or other context, but URI syntax is
complicated and subject to a wide variety of spoofing attacks. This tool allows
easy exercise of common sources of spoofing vulnerabilities to ensure
applications are robust in their display of URIs.

## Implementation

The tool is configured as a proxy server for the client application under test.
All of the client's HTTP requests are sent to the proxy. The proxy returns HTML
content such that the behavior of the client application can be tested. For
instance, for Chrome itself, the tester can examine the content of the omnibox
to verify that the origin is visible and unambiguously identified to the user.

## Testcases

Files in the testcases folder will be served as if they were served from any
URL, i.e. with the proxy running, visiting google.com/samplepathtest will serve
testcases/samplepathtest. Additional test cases can be added to the testcases
folder.

## Running

To run trickuri, run 'go run trickuri.go' in the source directory.

## Proxy configuration

The proxy may be configured in one of two ways:

1.  As a "static proxy", running on port 1270 (by default) of the machine
    running the proxy.
2.  As an "autoconfigured proxy" where the client pulls
    http://<IP/Hostname of computer running trickuri>:1270/proxy.pac as the proxy determination script.

The advantage of the latter configuration is that it allows the proxy to specify
that it should be bypassed for certain URLs, e.g. those used by SafeBrowsing,
component updates, etc. Such bypass helps limit the impact of the proxy on the
system under test.

## Certificate configuration

In order for the tool to be able to intercept HTTPS requests, its root
certificate needs to be trusted either by the browser or the OS. The root
certificate can be downloaded from http://localhost:1270/root.cer once the tool
is running.

## Flags

-p Sets the port in which the tool will listen, defaults to 1270.

-h Sets the port for the https server, defaults to 8443.

-d Sets the directory for certificate storage, defaults to ~/.trickuri
