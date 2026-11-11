QUIC Client Initial fixtures:

rfc9001-client-initial.hex: RFC 9001, Appendix A.2, protected client packet.
https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2

rfc9369-client-initial.hex: RFC 9369, Appendix A.2, QUIC v2 protected client packet.
https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A.2

Both are 1200-byte public protocol test vectors, copied without modification.
These fixtures exercise interoperable Initial key derivation, header protection,
AEAD authentication, CRYPTO framing and ClientHello extraction independently of
ProxyLane's synthetic packet generation.
