/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/** RFC5878 */
public enum AuthzDataFormat {
    X509_ATTR_CERT((byte) 0),
    SAML_ASSERTION((byte) 1),
    X509_ATTR_CERT_URL((byte) 2),
    SAML_ASSERTION_URL((byte) 3);

    private final byte value;
    private static final Map<Byte, AuthzDataFormat> MAP;

    AuthzDataFormat(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (AuthzDataFormat c : values()) {
            MAP.put(c.getValue(), c);
        }
    }

    public static AuthzDataFormat getDataFormat(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public static byte[] listToByteArray(List<AuthzDataFormat> list) {
        try (SilentByteArrayOutputStream bytes = new SilentByteArrayOutputStream(list.size())) {
            for (AuthzDataFormat f : list) {
                bytes.write(f.getValue());
            }
            return bytes.toByteArray();
        }
    }

    public static List<AuthzDataFormat> byteArrayToList(byte[] values) {
        List<AuthzDataFormat> list = new LinkedList<>();
        for (byte b : values) {
            list.add(getDataFormat(b));
        }
        return list;
    }
}
