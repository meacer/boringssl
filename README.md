# BoringSSL (`tai-server` Branch)

This branch adds CLI support to `bssl server` and `bssl client` for serving and testing **TLS Trust Anchor Identifiers (TAI)** (`draft-ietf-tls-trust-anchor-ids`), including a lightweight reverse-proxy mode (`-proxy`) to terminate TLS+TAI in front of an existing HTTP server (such as Apache).

## Summary of Changes

* **`tool/server.cc` (`bssl server`)**:
  * Added `-trust-anchor-id <relative-oid>` (e.g., `-trust-anchor-id 1.2.3`): Configures an `SSL_CREDENTIAL` (`SSL_CREDENTIAL_set1_trust_anchor_id` + `SSL_CREDENTIAL_set_must_match_issuer`) on the server's `SSL_CTX`, using either the provided `-key` / `-cert` PEM files or an auto-generated self-signed certificate. Also registers a default fallback credential so non-TAI clients can connect.
  * Added `-tai-fallback-cert <path>`: Specifies a distinct certificate chain (e.g., a standalone MTC) to use as the default fallback credential when the client does not match `-trust-anchor-id`, while `-cert` (e.g., a landmark-relative MTC) is served when `-trust-anchor-id` matches.
  * Added `-proxy <host:port>` (e.g., `-proxy 127.0.0.1:80`): Reverse-proxies decrypted TLS traffic bidirectionally to a backend HTTP server (e.g., Apache or Nginx).
* **`tool/client.cc` & `tool/transport_common.cc` (`bssl client`)**:
  * Logs whether the server's certificate matched the client's requested trust anchor ID (`SSL_peer_matched_trust_anchor`) and prints the server's available trust anchor IDs (`SSL_get0_peer_available_trust_anchors`).

## Building the Standalone `bssl` Binary

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bssl -j$(nproc)
strip --strip-all build/bssl
```

This produces a single ~2.7 MB self-contained executable (`build/bssl`) with no external `.so` dependencies beyond standard system libraries (`libc`, `libstdc++`).

## Serving a TAI-Enabled Test Site

### 1. In front of Apache (Reverse Proxy on Port 443)
Run `bssl server` on port 443 to terminate TLS 1.3 + TAI and forward HTTP traffic to Apache listening on `127.0.0.1:80`:

```bash
sudo ./build/bssl server \
  -accept 443 \
  -key /etc/ssl/private/site.key \
  -cert /etc/ssl/certs/site.pem \
  -trust-anchor-id 1.2.3 \
  -proxy 127.0.0.1:80 \
  -loop
```

### 2. Standalone Diagnostic Responder (`-www`)
To run without a backend HTTP server (responds with connection and handshake details on `GET /`):

```bash
./build/bssl server -accept 8443 -trust-anchor-id 1.2.3 -www -loop
```

## Verifying TAI Negotiation from the Command Line

Use `bssl client` with `-request-trust-anchors`:

```bash
echo -e "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n" | \
  ./build/bssl client -connect 127.0.0.1:8443 -request-trust-anchors 1.2.3
```

Example output showing TAI match:
```text
  [Verify] Peer matched trust anchor: yes
  [Verify] Server available trust anchors (4 bytes): 03 01 02 03
```

---

# BoringSSL (Upstream)

BoringSSL is a fork of OpenSSL that is designed to meet Google's needs.

Although BoringSSL is an open source project, it is not intended for general
use, as OpenSSL is. We don't recommend that third parties depend upon it. Doing
so is likely to be frustrating because there are no guarantees of API or ABI
stability.

Programs ship their own copies of BoringSSL when they use it and we update
everything as needed when deciding to make API changes. This allows us to
mostly avoid compromises in the name of compatibility. It works for us, but it
may not work for you.

BoringSSL arose because Google used OpenSSL for many years in various ways and,
over time, built up a large number of patches that were maintained while
tracking upstream OpenSSL. As Google's product portfolio became more complex,
more copies of OpenSSL sprung up and the effort involved in maintaining all
these patches in multiple places was growing steadily.

Currently BoringSSL is the SSL library in Chrome/Chromium, Android (but it's
not part of the NDK) and a number of other apps/programs.

Project links:

  * [API documentation](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html)
  * [Issue tracker](https://crbug.com/boringssl)
    * [Filing new (public) issues](https://crbug.com/boringssl/new)
  * [CI](https://ci.chromium.org/p/boringssl/g/main/console)
  * [Code review](https://boringssl-review.googlesource.com)
  * [Security Advisories](./docs/advisories/)

To file a security issue, use the [Chromium process](https://www.chromium.org/Home/chromium-security/reporting-security-bugs/) and mention in the report this is for BoringSSL. You can ignore the parts of the process that are specific to Chromium/Chrome.

There are other files in this directory which might be helpful:

  * [PORTING.md](./PORTING.md): how to port OpenSSL-using code to BoringSSL.
  * [BUILDING.md](./BUILDING.md): how to build BoringSSL
  * [INCORPORATING.md](./INCORPORATING.md): how to incorporate BoringSSL into a project.
  * [API-CONVENTIONS.md](./API-CONVENTIONS.md): general API conventions for BoringSSL consumers and developers.
  * [STYLE.md](./STYLE.md): rules and guidelines for coding style.
  * include/openssl: public headers with API documentation in comments. Also [available online](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html).
  * [FUZZING.md](./FUZZING.md): information about fuzzing BoringSSL.
  * [CONTRIBUTING.md](./CONTRIBUTING.md): how to contribute to BoringSSL.
  * [BREAKING-CHANGES.md](./BREAKING-CHANGES.md): notes on potentially-breaking changes.
  * [SANDBOXING.md](./SANDBOXING.md): notes on using BoringSSL in a sandboxed environment.
