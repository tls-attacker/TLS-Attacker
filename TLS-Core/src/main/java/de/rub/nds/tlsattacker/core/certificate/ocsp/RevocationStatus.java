/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
        String translated = null;
        translated = statusMap.get(input);
        return translated;
    }

    public static Integer translate(String input) {
        Integer translated = null;
        translated = statusMap.inverse().get(input);
        return translated;
    }
}
