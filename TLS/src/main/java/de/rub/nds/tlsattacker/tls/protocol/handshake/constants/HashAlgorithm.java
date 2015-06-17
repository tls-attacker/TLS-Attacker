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
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum HashAlgorithm {

    NONE((byte) 0, ""),
    MD5((byte) 1, "MD5"),
    SHA1((byte) 2, "SHA-1"),
    SHA224((byte) 3, "SHA-224"),
    SHA256((byte) 4, "SHA-256"),
    SHA384((byte) 5, "SHA-384"),
    SHA512((byte) 6, "SHA-512");

    private final byte value;

    private final String javaName;

    private static final Map<Byte, HashAlgorithm> MAP;

    private HashAlgorithm(byte value, String javaName) {
	this.value = value;
	this.javaName = javaName;
    }

    static {
	MAP = new HashMap<>();
	for (HashAlgorithm cm : HashAlgorithm.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HashAlgorithm getHashAlgorithm(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public String getJavaName() {
	return javaName;
    }
}
