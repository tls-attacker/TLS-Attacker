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
package de.rub.nds.tlsattacker.tls.protocol.handshake.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * http://tools.ietf.org/html/rfc5246#section-7.4.4
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum ClientCertificateType {

    RSA_SIGN((byte) 1),
    DSS_SIGN((byte) 2),
    RSA_FIXED_DH((byte) 3),
    DSS_FIXED_DH((byte) 4),
    RSA_EPHEMERAL_DH_RESERVED((byte) 5),
    DSS_EPHEMERAL_DH_RESERVED((byte) 6),
    FORTEZZA_DMS_RESERVED((byte) 20);

    /**
     * length of the ClientCertificateType in the TLS byte arrays
     */
    public static final int LENGTH = 1;

    private byte value;

    private static final Map<Byte, ClientCertificateType> MAP;

    private ClientCertificateType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (ClientCertificateType c : ClientCertificateType.values()) {
	    MAP.put(c.value, c);
	}
    }

    public static ClientCertificateType getClientCertificateType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }
}
