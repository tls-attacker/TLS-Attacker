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

/**
 * Symmetric cipher algorithm and its mapping to Java names
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum CipherAlgorithm {

    NULL(0, ""),
    RC4_128(16, "RC4"),
    DES_EDE_CBC(24, "DESede/CBC/NoPadding"),
    AES_128_CBC(16, "AES/CBC/NoPadding"),
    AES_256_CBC(32, "AES/CBC/NoPadding"),
    AES_128_GCM(16, "AES/GCM/NoPadding"),
    AES_256_GCM(32, "AES/GCM/NoPadding");

    CipherAlgorithm(int keySize, String javaName) {
	this.keySize = keySize;
	this.javaName = javaName;
    }

    private final int keySize;

    private final String javaName;

    public int getKeySize() {
	return keySize;
    }

    public String getJavaName() {
	return javaName;
    }
}
