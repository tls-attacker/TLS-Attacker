/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public enum ExtensionType {
    SERVER_NAME_INDICATION(new byte[] {(byte) 0, (byte) 0}),
    MAX_FRAGMENT_LENGTH(new byte[] {(byte) 0, (byte) 1}),
    CLIENT_CERTIFICATE_URL(new byte[] {(byte) 0, (byte) 2}),
    TRUSTED_CA_KEYS(new byte[] {(byte) 0, (byte) 3}),
    TRUNCATED_HMAC(new byte[] {(byte) 0, (byte) 4}),
    STATUS_REQUEST(new byte[] {(byte) 0, (byte) 5}),
    USER_MAPPING(new byte[] {(byte) 0, (byte) 6}),
    CLIENT_AUTHZ(new byte[] {(byte) 0, (byte) 7}),
    SERVER_AUTHZ(new byte[] {(byte) 0, (byte) 8}),
    CERT_TYPE(new byte[] {(byte) 0, (byte) 9}),
    ELLIPTIC_CURVES(new byte[] {(byte) 0, (byte) 10}),
    EC_POINT_FORMATS(new byte[] {(byte) 0, (byte) 11}),
    SRP(new byte[] {(byte) 0, (byte) 12}),
    SIGNATURE_AND_HASH_ALGORITHMS(new byte[] {(byte) 0, (byte) 13}),
    USE_SRTP(new byte[] {(byte) 0, (byte) 14}),
    HEARTBEAT(new byte[] {(byte) 0, (byte) 15}),
    ALPN(new byte[] {(byte) 0, (byte) 16}),
    STATUS_REQUEST_V2(new byte[] {(byte) 0, (byte) 17}),
    SIGNED_CERTIFICATE_TIMESTAMP(new byte[] {(byte) 0, (byte) 18}),
    CLIENT_CERTIFICATE_TYPE(new byte[] {(byte) 0, (byte) 19}),
    SERVER_CERTIFICATE_TYPE(new byte[] {(byte) 0, (byte) 20}),
    PADDING(new byte[] {(byte) 0, (byte) 21}),
    ENCRYPT_THEN_MAC(new byte[] {(byte) 0, (byte) 22}),
    EXTENDED_MASTER_SECRET(new byte[] {(byte) 0, (byte) 23}),
    TOKEN_BINDING(new byte[] {(byte) 0, (byte) 24}),
    CACHED_INFO(new byte[] {(byte) 0, (byte) 25}),
    RECORD_SIZE_LIMIT(new byte[] {(byte) 0, (byte) 28}),
    PWD_PROTECT(new byte[] {(byte) 0, (byte) 29}),
    PWD_CLEAR(new byte[] {(byte) 0, (byte) 30}),
    PASSWORD_SALT(new byte[] {(byte) 0, (byte) 31}),
    SESSION_TICKET(new byte[] {(byte) 0, (byte) 35}),
    EXTENDED_RANDOM(new byte[] {(byte) 0, (byte) 40}), // Shares same IANA ID
    // as old keyshare
    // extension.
    PRE_SHARED_KEY(new byte[] {(byte) 0, (byte) 41}),
    EARLY_DATA(new byte[] {(byte) 0, (byte) 42}),
    SUPPORTED_VERSIONS(new byte[] {(byte) 0, (byte) 43}),
    COOKIE(new byte[] {0x00, (byte) 44}),
    PSK_KEY_EXCHANGE_MODES(new byte[] {(byte) 0, (byte) 45}),
    CERTIFICATE_AUTHORITIES(new byte[] {(byte) 0, (byte) 47}),
    OID_FILTERS(new byte[] {(byte) 0, (byte) 48}),
    POST_HANDSHAKE_AUTH(new byte[] {(byte) 0, (byte) 49}),
    SIGNATURE_ALGORITHMS_CERT(new byte[] {(byte) 0, (byte) 50}),
    KEY_SHARE(new byte[] {(byte) 0, (byte) 51}),
    CONNECTION_ID(new byte[] {(byte) 0, (byte) 54}),
    RENEGOTIATION_INFO(new byte[] {(byte) 0xFF, (byte) 0x01}),
    ENCRYPTED_SERVER_NAME_INDICATION(new byte[] {(byte) 0xFF, (byte) 0xCE}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_07(new byte[] {(byte) 0xFF, (byte) 0x02}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_08(new byte[] {(byte) 0xFF, (byte) 0x08}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_09(new byte[] {(byte) 0xFF, (byte) 0x09}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_10(new byte[] {(byte) 0xFF, (byte) 0x0a}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_11(new byte[] {(byte) 0xFF, (byte) 0x0b}),
    ENCRYPTED_CLIENT_HELLO_DRAFT_12(new byte[] {(byte) 0xFF, (byte) 0x0c}),
    ENCRYPTED_CLIENT_HELLO(new byte[] {(byte) 0xFE, (byte) 0x0D}),

    // GREASE constants
    GREASE_00(new byte[] {(byte) 0x0A, (byte) 0x0A}),
    GREASE_01(new byte[] {(byte) 0x1A, (byte) 0x1A}),
    GREASE_02(new byte[] {(byte) 0x2A, (byte) 0x2A}),
    GREASE_03(new byte[] {(byte) 0x3A, (byte) 0x3A}),
    GREASE_04(new byte[] {(byte) 0x4A, (byte) 0x4A}),
    GREASE_05(new byte[] {(byte) 0x5A, (byte) 0x5A}),
    GREASE_06(new byte[] {(byte) 0x6A, (byte) 0x6A}),
    GREASE_07(new byte[] {(byte) 0x7A, (byte) 0x7A}),
    GREASE_08(new byte[] {(byte) 0x8A, (byte) 0x8A}),
    GREASE_09(new byte[] {(byte) 0x9A, (byte) 0x9A}),
    GREASE_10(new byte[] {(byte) 0xAA, (byte) 0xAA}),
    GREASE_11(new byte[] {(byte) 0xBA, (byte) 0xBA}),
    GREASE_12(new byte[] {(byte) 0xCA, (byte) 0xCA}),
    GREASE_13(new byte[] {(byte) 0xDA, (byte) 0xDA}),
    GREASE_14(new byte[] {(byte) 0xEA, (byte) 0xEA}),
    GREASE_15(new byte[] {(byte) 0xFA, (byte) 0xFA}),

    UNKNOWN(new byte[0]);

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
        if (value.length == 2) {
            return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
        } else {
            return -1;
        }
    }

    public static ExtensionType getExtensionType(byte[] value) {
        ExtensionType type = MAP.get(valueToInt(value));
        if (type == null) {
            return UNKNOWN;
        }
        return type;
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

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }

    public static List<ExtensionType> getSendable() {
        List<ExtensionType> list = new LinkedList<>();
        list.add(ALPN);
        list.add(CACHED_INFO);
        list.add(CERT_TYPE);
        list.add(CLIENT_AUTHZ);
        list.add(CLIENT_CERTIFICATE_TYPE);
        list.add(CLIENT_CERTIFICATE_URL);
        list.add(EARLY_DATA);
        list.add(EC_POINT_FORMATS);
        list.add(ELLIPTIC_CURVES);
        list.add(ENCRYPT_THEN_MAC);
        list.add(EXTENDED_MASTER_SECRET);
        list.add(HEARTBEAT);
        list.add(KEY_SHARE);
        list.add(EXTENDED_RANDOM);
        list.add(MAX_FRAGMENT_LENGTH);
        list.add(PADDING);
        list.add(PRE_SHARED_KEY);
        list.add(PSK_KEY_EXCHANGE_MODES);
        list.add(RENEGOTIATION_INFO);
        list.add(SERVER_AUTHZ);
        list.add(SERVER_CERTIFICATE_TYPE);
        list.add(SERVER_NAME_INDICATION);
        list.add(SESSION_TICKET);
        list.add(SIGNATURE_AND_HASH_ALGORITHMS);
        list.add(SIGNATURE_ALGORITHMS_CERT);
        list.add(SIGNED_CERTIFICATE_TIMESTAMP);
        list.add(SRP);
        list.add(STATUS_REQUEST);
        list.add(STATUS_REQUEST_V2);
        list.add(SUPPORTED_VERSIONS);
        list.add(TOKEN_BINDING);
        list.add(TRUNCATED_HMAC);
        list.add(TRUSTED_CA_KEYS);
        list.add(USE_SRTP);
        list.add(COOKIE);
        list.add(RECORD_SIZE_LIMIT);
        list.add(CONNECTION_ID);
        list.add(ENCRYPTED_CLIENT_HELLO);

        return list;
    }

    public static List<ExtensionType> getReceivable() {
        List<ExtensionType> list = new LinkedList<>();
        list.add(ALPN);
        list.add(CACHED_INFO);
        list.add(CERT_TYPE);
        list.add(CLIENT_AUTHZ);
        list.add(CLIENT_CERTIFICATE_TYPE);
        list.add(CLIENT_CERTIFICATE_URL);
        list.add(EARLY_DATA);
        list.add(EC_POINT_FORMATS);
        list.add(ELLIPTIC_CURVES);
        list.add(ENCRYPT_THEN_MAC);
        list.add(EXTENDED_MASTER_SECRET);
        list.add(HEARTBEAT);
        list.add(KEY_SHARE);
        list.add(EXTENDED_RANDOM);
        list.add(MAX_FRAGMENT_LENGTH);
        list.add(PADDING);
        list.add(PRE_SHARED_KEY);
        list.add(PSK_KEY_EXCHANGE_MODES);
        list.add(RENEGOTIATION_INFO);
        list.add(SERVER_AUTHZ);
        list.add(SERVER_CERTIFICATE_TYPE);
        list.add(SERVER_NAME_INDICATION);
        list.add(SESSION_TICKET);
        list.add(SIGNATURE_AND_HASH_ALGORITHMS);
        list.add(SIGNATURE_ALGORITHMS_CERT);
        list.add(SIGNED_CERTIFICATE_TIMESTAMP);
        list.add(SRP);
        list.add(STATUS_REQUEST);
        list.add(STATUS_REQUEST_V2);
        list.add(SUPPORTED_VERSIONS);
        list.add(TOKEN_BINDING);
        list.add(TRUNCATED_HMAC);
        list.add(TRUSTED_CA_KEYS);
        list.add(USE_SRTP);
        list.add(COOKIE);
        list.add(RECORD_SIZE_LIMIT);
        list.add(ENCRYPTED_CLIENT_HELLO);
        list.add(CONNECTION_ID);

        return list;
    }

    public static List<ExtensionType> getImplemented() {
        List<ExtensionType> list = new LinkedList<>();
        list.add(EARLY_DATA);
        list.add(EC_POINT_FORMATS);
        list.add(ELLIPTIC_CURVES);
        list.add(EXTENDED_MASTER_SECRET);
        list.add(KEY_SHARE);
        list.add(MAX_FRAGMENT_LENGTH);
        list.add(PADDING);
        list.add(PRE_SHARED_KEY);
        list.add(PSK_KEY_EXCHANGE_MODES);
        list.add(SERVER_NAME_INDICATION);
        list.add(SIGNATURE_AND_HASH_ALGORITHMS);
        list.add(SIGNATURE_ALGORITHMS_CERT);
        list.add(SUPPORTED_VERSIONS);
        list.add(TOKEN_BINDING);
        list.add(RENEGOTIATION_INFO);
        list.add(HEARTBEAT);
        list.add(EXTENDED_RANDOM);
        list.add(COOKIE);
        list.add(RECORD_SIZE_LIMIT);
        list.add(CONNECTION_ID);
        list.add(ENCRYPTED_CLIENT_HELLO);

        return list;
    }

    public static boolean allowedInEncryptedExtensions(ExtensionType extType) {
        switch (extType) {
            case SERVER_NAME_INDICATION:
            case MAX_FRAGMENT_LENGTH:
            case ELLIPTIC_CURVES:
            case USE_SRTP:
            case HEARTBEAT:
            case ALPN:
            case CLIENT_CERTIFICATE_TYPE:
            case SERVER_CERTIFICATE_TYPE:
            case EARLY_DATA:
            case RECORD_SIZE_LIMIT:
                return true;
        }
        return false;
    }

    public static List<ExtensionType> getNonTls13Extensions() {
        List<ExtensionType> list = new LinkedList<>();
        list.add(EXTENDED_MASTER_SECRET);
        list.add(EXTENDED_RANDOM);
        list.add(ENCRYPT_THEN_MAC);
        list.add(SRP);
        list.add(TRUNCATED_HMAC);
        list.add(RENEGOTIATION_INFO);
        return list;
    }

    public static List<ExtensionType> getTls13OnlyExtensions() {
        List<ExtensionType> list = new LinkedList<>();
        list.add(EARLY_DATA);
        list.add(KEY_SHARE);
        return list;
    }
}
