/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum CipherSuite {

    // Null
    TLS_NULL_WITH_NULL_NULL(0x0000),
    // RSA
    TLS_RSA_WITH_NULL_MD5(0x0001),
    TLS_RSA_WITH_NULL_SHA(0x0002),
    TLS_RSA_WITH_NULL_SHA256(0x003B),
    TLS_RSA_WITH_RC4_128_MD5(0x0004),
    TLS_RSA_WITH_RC4_128_SHA(0x0005),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000A),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x002F),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C),
    TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D),
    // DH
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x000D),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x0010),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x0013),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x0030),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x0031),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x0036),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x0037),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x003E),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x003F),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x0068),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x0069),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B),
    // Anonymous DH
    TLS_DH_anon_WITH_RC4_128_MD5(0x0018),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(0x001B),
    TLS_DH_anon_WITH_AES_128_CBC_SHA(0x0034),
    TLS_DH_anon_WITH_AES_256_CBC_SHA(0x003A),
    TLS_DH_anon_WITH_AES_128_CBC_SHA256(0x006C),
    TLS_DH_anon_WITH_AES_256_CBC_SHA256(0x006D),
    // ECDH(E)
    TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005),
    TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A),
    TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B),
    TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F),
    TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014),
    TLS_ECDH_anon_WITH_NULL_SHA(0xC015),
    TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B);

    private int value;

    private static final Map<Integer, CipherSuite> MAP;

    private CipherSuite(int value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (CipherSuite c : CipherSuite.values()) {
	    MAP.put(c.value, c);
	}
    }

    private static int valueToInt(byte[] value) {
	return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static CipherSuite getCipherSuite(byte[] value) {
	return MAP.get(valueToInt(value));
    }

    public static CipherSuite getCipherSuite(int value) {
	return MAP.get(value);
    }

    public byte[] getByteValue() {
	return ArrayConverter.intToBytes(value, 2);
    }

    public int getValue() {
	return value;
    }

    /**
     * Returns true in case the cipher suite enforces ephemeral keys. This is
     * the case for ECDHE and DHE cipher suites.
     * 
     * @return
     */
    public boolean isEphemeral() {
	return this.name().contains("DHE_");
    }

    /**
     * Returns true in case the cipher suite is an AEAD cipher suite.
     * 
     * @return
     */
    public boolean isAEAD() {
	return (this.name().contains("_GCM") || this.name().contains("_CCM") || this.name().contains("_OCB"));
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
	list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
	list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
	return list;
    }
}
