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
package de.rub.nds.tlsattacker.tls.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * EllipticCurveType defined in rfc4492:
 * https://tools.ietf.org/html/rfc4492#section-5.4
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum EllipticCurveType {

    EXPLICIT_PRIME((byte) 1),
    EXPLICIT_CHAR2((byte) 2),
    NAMED_CURVE((byte) 3);

    /** length of the EllipticCurveType in the TLS byte arrays */
    public static final int LENGTH = 1;

    private byte value;

    private static final Map<Byte, EllipticCurveType> MAP;

    private EllipticCurveType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (EllipticCurveType c : EllipticCurveType.values()) {
	    MAP.put(c.value, c);
	}
    }

    public static EllipticCurveType getCurveType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }
}
