
package de.rub.nds.tlsattacker.core.constants;

/**
 * An enum which can give indications on how to build the protocol stack
 */
public enum ProtocolConfiguration {
    SSL2,
    TLS,
    STARTTLS,
    DTLS,
    OPENVPN,
    QUIC,
}
