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

Chunked bodies use hexadecimal size lines terminated by CRLF. ExfilGuard
validates the complete RFC 9112 chunk-extension grammar, including token and
quoted-string values, and forwards valid size lines unchanged. This preserves
signed chunk extensions. Bare-LF lines, extra or embedded carriage returns,
controls, malformed quoting, and trailing syntax are rejected. Invalid request
framing receives a `400 Bad Request` response and closes the connection.

The same validation applies to chunked origin responses. If malformed framing
is found after the origin response headers have already been sent downstream,
ExfilGuard closes the downstream connection instead of appending a second HTTP
response.

## Legacy or Lenient Upstreams

Some origins incorrectly send `Content-Length: 0` on a `204 No Content`
response. ExfilGuard accepts this narrow HTTP/1 compatibility case, removes the
header, and forwards only the empty 204 response. It closes the upstream and
downstream connections after the response to prevent stray origin bytes from
being reused as another response. Nonzero lengths, malformed or duplicate
length fields, and any `Transfer-Encoding` on 204 still produce a 502.

Some legacy servers treat a missing length as "read until close". On keep-alive
connections that can lead to timeouts or other odd behavior. If you must talk
to such servers, make sure clients send `Content-Length` or
`Transfer-Encoding`, or send `Connection: close` so EOF becomes an explicit
delimiter.
