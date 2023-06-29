/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

public class RevocationStatus {
    private static final BiMap<Integer, String> statusMap = HashBiMap.create();

    static {
        statusMap.put(0, "good");
        statusMap.put(1, "revoked");
        statusMap.put(2, "unknown");
    }

    public static String translate(Integer input) {
        String translated;
        translated = statusMap.get(input);
        return translated;
    }

    public static Integer translate(String input) {
        Integer translated;
        translated = statusMap.inverse().get(input);
        return translated;
    }
}
