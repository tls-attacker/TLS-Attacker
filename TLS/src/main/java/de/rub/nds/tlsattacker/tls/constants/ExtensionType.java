/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.tls.protocol.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionHandler;

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
    ELLIPTIC_CURVES(new byte[] { (byte) 0, (byte) 10 }),
    EC_POINT_FORMATS(new byte[] { (byte) 0, (byte) 11 }),
    SIGNATURE_AND_HASH_ALGORITHMS(new byte[] { (byte) 0, (byte) 13 }),
    HEARTBEAT(new byte[] { (byte) 0, (byte) 15 });

    private static final Logger LOGGER = LogManager.getLogger(ExtensionType.class);

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
	return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static ExtensionType getExtensionType(byte[] value) {
	return MAP.get(valueToInt(value));
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

    public ExtensionHandler<? extends ExtensionMessage> getExtensionHandler() {
	ExtensionHandler<? extends ExtensionMessage> eh = null;
	switch (this) {
	    case SERVER_NAME_INDICATION:
		eh = ServerNameIndicationExtensionHandler.getInstance();
		break;
	    case MAX_FRAGMENT_LENGTH:
		eh = MaxFragmentLengthExtensionHandler.getInstance();
		break;
	    case EC_POINT_FORMATS:
		eh = ECPointFormatExtensionHandler.getInstance();
		break;
	    case ELLIPTIC_CURVES:
		eh = EllipticCurvesExtensionHandler.getInstance();
		break;
	    case SIGNATURE_AND_HASH_ALGORITHMS:
		eh = SignatureAndHashAlgorithmsExtensionHandler.getInstance();
		break;
	    case HEARTBEAT:
		eh = HeartbeatExtensionHandler.getInstance();
		break;
	    default:
	}
	if (eh == null) {
	    throw new UnsupportedOperationException("Extension not supported yet");
	}
	return eh;
    }
}
