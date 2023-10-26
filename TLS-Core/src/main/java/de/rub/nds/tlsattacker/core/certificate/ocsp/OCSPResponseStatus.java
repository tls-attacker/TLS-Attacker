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

public class OCSPResponseStatus {

    private static final BiMap<Integer, String> statusMap = HashBiMap.create();

    static {
        statusMap.put(1, "malformedRequest");
        statusMap.put(2, "internalError");
        statusMap.put(3, "tryLater");
        statusMap.put(5, "sigRequired");
        statusMap.put(6, "unauthorized");
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
