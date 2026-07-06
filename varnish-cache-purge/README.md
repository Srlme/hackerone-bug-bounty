# Vulnerability: Unauthenticated Varnish Cache Purge (Configuration Bypass)

## Executive Summary
During a security assessment of the application's web infrastructure, a critical misconfiguration was identified in the reverse proxy layer (**Varnish Cache**). The server was found to accept administrative cache invalidation (eviction) requests via the `PURGE` HTTP method from unauthenticated external users. This vulnerability stems from the absence of proper Access Control List (ACL) restrictions.

## Vulnerability Analysis & Mechanics
Varnish Cache utilizes dedicated HTTP verbs, such as `PURGE` or `BAN`, to clear cached web pages from memory when backend data updates. In a secure deployment, these administrative methods must be strictly restricted to `localhost` or specific internal infrastructure IP addresses using the Varnish Configuration Language (VCL):

```vcl
# Example of the missing secure configuration:
acl purge {
    "localhost";
    "127.0.0.1";
}

sub vcl_recv {
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed."));
        }
        return (purge);
    }
}
```
Due to the omission of this access check within the configuration file, the proxy server processed administrative eviction commands originating from any external IP address on the internet.



# Proof of Concept (PoC)

## 1. Initial Discovery
The behavior was initially identified during automated footprinting of the infrastructure using Nuclei, which triggered the [unauthenticated-varnish-cache-purge] flag, signaling an anomalous server response to non-standard HTTP methods.

## 2. Manual Validation
Using Burp Suite Repeater, a raw HTTP request was crafted using the PURGE method directed at the target domain example.com:

<img width="595" height="220" alt="image" src="https://github.com/user-attachments/assets/609b8aee-a1e4-42cc-9d0e-41f908472b4e" />

## 3. Server Response
The Varnish server successfully processed the administrative cache eviction command for the root path and returned a 200 OK status with a confirmation JSON payload:

<img width="615" height="439" alt="image" src="https://github.com/user-attachments/assets/dca2af76-1a79-4c8a-a92a-b3038dd1d594" />

# Severity & Impact Evaluation
**Business Logic Disruption**: An attacker can continuously flush the cache for critical pages, preventing users from receiving properly cached content or breaking the functionality of dynamic site modules.

**Denial of Service (DoS) via Backend Resource Exhaustion**: The Varnish caching layer is deployed specifically to shield heavy application backends (in this instance, Next.js SSR and underlying databases) from resource exhaustion. By script-purging high-traffic assets or heavy API endpoints continuously, an attacker forces Varnish to forward every single user request directly to the backend. This results in a rapid spike in server CPU utilization and database connection pool starvation, potentially causing a full or partial Denial of Service (DoS).

# Remediation Guidelines
**Implement IP-based ACLs**: Explicitly define a trusted IP range within the Varnish configuration (default.vcl) authorized to trigger cache eviction processes.

**Drop Unauthorized Methods Early**: Ensure that any incoming request utilizing the PURGE method from an untrusted origin drops immediately, returning a 405 Method Not Allowed response before any backend logic or eviction occurs.
