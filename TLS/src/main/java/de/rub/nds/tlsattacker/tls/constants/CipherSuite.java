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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum CipherSuite {

    // Null
    TLS_NULL_WITH_NULL_NULL(new byte[] { (byte) 0x00, (byte) 0x00 }),
    // RSA
    TLS_RSA_WITH_NULL_MD5(new byte[] { (byte) 0x00, (byte) 0x01 }),
    TLS_RSA_WITH_NULL_SHA(new byte[] { (byte) 0x00, (byte) 0x02 }),
    TLS_RSA_WITH_NULL_SHA256(new byte[] { (byte) 0x00, (byte) 0x3B }),
    TLS_RSA_WITH_RC4_128_MD5(new byte[] { (byte) 0x00, (byte) 0x04 }),
    TLS_RSA_WITH_RC4_128_SHA(new byte[] { (byte) 0x00, (byte) 0x05 }),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x0A }),
    TLS_RSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x2F }),
    TLS_RSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x35 }),
    TLS_RSA_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x3C }),
    TLS_RSA_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x3D }),
    // DH
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x0D }),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x10 }),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x13 }),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x16 }),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x30 }),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x31 }),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x32 }),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x33 }),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x36 }),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x37 }),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x38 }),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x39 }),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x3E }),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x3F }),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x40 }),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x67 }),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x68 }),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x69 }),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x6A }),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x6B }),
    // Anonymous DH
    TLS_DH_anon_WITH_RC4_128_MD5(new byte[] { (byte) 0x00, (byte) 0x18 }),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x1B }),
    TLS_DH_anon_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x34 }),
    TLS_DH_anon_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0x00, (byte) 0x3A }),
    TLS_DH_anon_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x6C }),
    TLS_DH_anon_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0x00, (byte) 0x6D }),
    // ECDH(E)
    TLS_ECDH_ECDSA_WITH_NULL_SHA(new byte[] { (byte) 0xC0, (byte) 0x01 }),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA(new byte[] { (byte) 0xC0, (byte) 0x02 }),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x03 }),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x04 }),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x05 }),
    TLS_ECDHE_ECDSA_WITH_NULL_SHA(new byte[] { (byte) 0xC0, (byte) 0x06 }),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(new byte[] { (byte) 0xC0, (byte) 0x07 }),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x08 }),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x09 }),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x0A }),
    TLS_ECDH_RSA_WITH_NULL_SHA(new byte[] { (byte) 0xC0, (byte) 0x0B }),
    TLS_ECDH_RSA_WITH_RC4_128_SHA(new byte[] { (byte) 0xC0, (byte) 0x0C }),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x0D }),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x0E }),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x0F }),
    TLS_ECDHE_RSA_WITH_NULL_SHA(new byte[] { (byte) 0xC0, (byte) 0x10 }),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(new byte[] { (byte) 0xC0, (byte) 0x11 }),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x12 }),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x13 }),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x14 }),
    TLS_ECDH_anon_WITH_NULL_SHA(new byte[] { (byte) 0xC0, (byte) 0x15 }),
    TLS_ECDH_anon_WITH_RC4_128_SHA(new byte[] { (byte) 0xC0, (byte) 0x16 }),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x17 }),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x18 }),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA(new byte[] { (byte) 0xC0, (byte) 0x19 }),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0xC0, (byte) 0x23 }),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA256(new byte[] { (byte) 0xC0, (byte) 0x24 }),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(new byte[] { (byte) 0xC0, (byte) 0x27 }),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(new byte[] { (byte) 0xC0, (byte) 0x28 }),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(new byte[] { (byte) 0xC0, (byte) 0x2F }),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(new byte[] { (byte) 0xC0, (byte) 0x30 }),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[] { (byte) 0xC0, (byte) 0x76 }),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(new byte[] { (byte) 0xC0, (byte) 0x77 }),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[] { (byte) 0xC0, (byte) 0x8A }),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[] { (byte) 0xC0, (byte) 0x8B });

    private byte[] value;

    private static final Map<Integer, CipherSuite> MAP;

    private CipherSuite(byte[] value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (CipherSuite c : CipherSuite.values()) {
	    MAP.put(valueToInt(c.value), c);
	}
    }

    private static int valueToInt(byte[] value) {
	return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static CipherSuite getCipherSuite(byte[] value) {
	return MAP.get(valueToInt(value));
    }

    public byte[] getValue() {
	return value;
    }

    /**
     * Returns true in case the ciphersuite enforces ephemeral keys. This is the
     * case for ECDHE and DHE ciphersuites.
     * 
     * @return
     */
    public boolean isEphemeral() {
	return this.name().contains("DHE_");
    }

    public static List<CipherSuite> getImplemented() {
	List<CipherSuite> list = new LinkedList<>();
	list.add(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_RSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_RSA_WITH_AES_128_CBC_SHA256);
	list.add(TLS_RSA_WITH_AES_256_CBC_SHA256);
	list.add(TLS_RSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
	list.add(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
	list.add(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
	list.add(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
	list.add(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
	list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
	list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
	list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
	return list;
    }
}
