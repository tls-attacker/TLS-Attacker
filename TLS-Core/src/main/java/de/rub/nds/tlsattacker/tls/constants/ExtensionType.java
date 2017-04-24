/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.UnknownExtensionHandler;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum ExtensionType {

    SERVER_NAME_INDICATION(new byte[] { (byte) 0, (byte) 0 }),
    MAX_FRAGMENT_LENGTH(new byte[] { (byte) 0, (byte) 1 }),
    CLIENT_CERTIFICATE_URL(new byte[] { (byte) 0, (byte) 2 }),
    TRUSTED_CA_KEYS(new byte[] { (byte) 0, (byte) 3 }),
    TRUNCATED_HMAC(new byte[] { (byte) 0, (byte) 4 }),
    STATUS_REQUEST(new byte[] { (byte) 0, (byte) 5 }),
    USER_MAPPING(new byte[] { (byte) 0, (byte) 6 }),
    CLIENT_AUTHZ(new byte[] { (byte) 0, (byte) 7 }),
    SERVER_AUTHZ(new byte[] { (byte) 0, (byte) 8 }),
    CERT_TYPE(new byte[] { (byte) 0, (byte) 9 }),
    ELLIPTIC_CURVES(new byte[] { (byte) 0, (byte) 10 }),
    EC_POINT_FORMATS(new byte[] { (byte) 0, (byte) 11 }),
    SRP(new byte[] { (byte) 0, (byte) 12 }),
    SIGNATURE_AND_HASH_ALGORITHMS(new byte[] { (byte) 0, (byte) 13 }),
    USE_SRTP(new byte[] { (byte) 0, (byte) 14 }),
    HEARTBEAT(new byte[] { (byte) 0, (byte) 15 }),
    ALPN(new byte[] { (byte) 0, (byte) 16 }),
    STATUS_REQUEST_V2(new byte[] { (byte) 0, (byte) 17 }),
    SIGNED_CERTIFICATE_TIMESTAMP(new byte[] { (byte) 0, (byte) 18 }),
    CLIENT_CERTIFICATE_TYPE(new byte[] { (byte) 0, (byte) 19 }),
    SERVER_CERTIFICATE_TYPE(new byte[] { (byte) 0, (byte) 20 }),
    PADDING(new byte[] { (byte) 0, (byte) 21 }),
    ENCRYPT_THEN_MAC(new byte[] { (byte) 0, (byte) 22 }),
    EXTENDED_MASTER_SECRET(new byte[] { (byte) 0, (byte) 23 }),
    TOKEN_BINDING(new byte[] { (byte) 0, (byte) 24 }),
    CACHED_INFO(new byte[] { (byte) 0, (byte) 25 }),
    SESSION_TICKET(new byte[] { (byte) 0, (byte) 35 }),
    SUPPORTED_VERSIONS(new byte[] { (byte) 0, (byte) 43 }),
    RENEGOTIATION_INFO(new byte[] { (byte) 0xFF, (byte) 0x01 }),

    UNKNOWN(new byte[0]);

    private byte[] value;

    private static final Map<Integer, ExtensionType> MAP;

    private ExtensionType(byte[] value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ExtensionType c : ExtensionType.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length == 2) {
            return (value[0] & 0xff) << 8 | (value[1] & 0xff);
        } else {
            return -1;
        }
    }

    public static ExtensionType getExtensionType(byte[] value) {
        ExtensionType type = MAP.get(valueToInt(value));
        if (type == null) {
            return UNKNOWN;
        }
        return type;
    }

    public byte[] getValue() {
        return value;
    }

    public byte getMajor() {
        return value[0];
    }

    public byte getMinor() {
        return value[1];
    }
}
