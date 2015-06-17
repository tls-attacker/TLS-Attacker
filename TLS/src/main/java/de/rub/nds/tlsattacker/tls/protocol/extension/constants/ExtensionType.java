/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.extension.constants;

import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.SignatureAndHashAlgorithmsExtensionHandler;
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

    public ExtensionHandler getExtensionHandler() {
	ExtensionHandler eh = null;
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
	}
	if (eh == null) {
	    throw new UnsupportedOperationException("Extension not supported yet");
	}
	return eh;
    }
}
