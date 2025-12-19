# HTTP/1.1 Request Framing

ExfilGuard parses HTTP/1.1 request bodies according to RFC 9112:

- If `Transfer-Encoding` is present, it defines the body framing.
- Else if `Content-Length` is present, it defines the body length.
- Else the body length is `0` for HTTP/1.1 keep-alive connections.

This means a request without `Content-Length` or `Transfer-Encoding` is treated
as having no body, and any bytes after the header terminator are parsed as the
next request on the same connection. ExfilGuard does not read until EOF because
EOF is only a valid delimiter when the connection is being closed.

## Legacy or Lenient Upstreams

Some legacy servers treat a missing length as "read until close". With
keep-alive connections this can lead to timeouts or unexpected behavior. If you
must communicate with such servers, ensure clients send a `Content-Length` or
`Transfer-Encoding`, or have the client send `Connection: close` so EOF becomes
an explicit delimiter.
