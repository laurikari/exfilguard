# HTTP/1.1 Request Framing

ExfilGuard parses HTTP/1.1 request bodies according to RFC 9112. HTTP/1.0
requests are not supported.

- If `Transfer-Encoding` is present, it defines the body framing.
- Else if `Content-Length` is present, it defines the body length.
- Else the body length is `0` for HTTP/1.1 keep-alive connections.

If a request has neither `Content-Length` nor `Transfer-Encoding`, ExfilGuard
treats it as having no body. Any bytes after the header terminator belong to
the next request on the same connection. ExfilGuard does not read until EOF,
because EOF is only a valid delimiter when the connection is being closed.

## Legacy or Lenient Upstreams

Some legacy servers treat a missing length as "read until close". On keep-alive
connections that can lead to timeouts or other odd behavior. If you must talk
to such servers, make sure clients send `Content-Length` or
`Transfer-Encoding`, or send `Connection: close` so EOF becomes an explicit
delimiter.
