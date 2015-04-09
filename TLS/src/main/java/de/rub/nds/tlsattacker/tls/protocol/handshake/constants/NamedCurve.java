/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
public enum NamedCurve {

    SECT163K1(new byte[] { (byte) 0, (byte) 1 }),
    SECT163R1(new byte[] { (byte) 0, (byte) 2 }),
    SECT163R2(new byte[] { (byte) 0, (byte) 3 }),
    SECT193R1(new byte[] { (byte) 0, (byte) 4 }),
    SECT193R2(new byte[] { (byte) 0, (byte) 5 }),
    SECT233K1(new byte[] { (byte) 0, (byte) 6 }),
    SECT233R1(new byte[] { (byte) 0, (byte) 7 }),
    SECT239K1(new byte[] { (byte) 0, (byte) 8 }),
    SECT283K1(new byte[] { (byte) 0, (byte) 9 }),
    SECT283R1(new byte[] { (byte) 0, (byte) 10 }),
    SECT409K1(new byte[] { (byte) 0, (byte) 11 }),
    SECT409R1(new byte[] { (byte) 0, (byte) 12 }),
    SECT571K1(new byte[] { (byte) 0, (byte) 13 }),
    SECT571R1(new byte[] { (byte) 0, (byte) 14 }),
    SECP160K1(new byte[] { (byte) 0, (byte) 15 }),
    SECP160R1(new byte[] { (byte) 0, (byte) 16 }),
    SECP160R2(new byte[] { (byte) 0, (byte) 17 }),
    SECP192K1(new byte[] { (byte) 0, (byte) 18 }),
    SECP192R1(new byte[] { (byte) 0, (byte) 19 }),
    SECP224K1(new byte[] { (byte) 0, (byte) 20 }),
    SECP224R1(new byte[] { (byte) 0, (byte) 21 }),
    SECP256K1(new byte[] { (byte) 0, (byte) 22 }),
    SECP256R1(new byte[] { (byte) 0, (byte) 23 }),
    SECP384R1(new byte[] { (byte) 0, (byte) 24 }),
    SECP521R1(new byte[] { (byte) 0, (byte) 25 });

    public static final int LENGTH = 2;

    private byte[] value;

    private static final Map<Integer, NamedCurve> MAP;

    private NamedCurve(byte[] value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (NamedCurve c : NamedCurve.values()) {
	    MAP.put(valueToInt(c.value), c);
	}
    }

    private static int valueToInt(byte[] value) {
	return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static NamedCurve getNamedCurve(byte[] value) {
	return MAP.get(valueToInt(value));
    }

    public byte[] getValue() {
	return value;
    }

    public int getIntValue() {
	return valueToInt(value);
    }
}
