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
 * Name Type for Server Name Indication
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum NameType {

    HOST_NAME((byte) 0);

    private byte value;

    private static final Map<Byte, NameType> MAP;

    private NameType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (NameType cm : NameType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static NameType getNameType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
