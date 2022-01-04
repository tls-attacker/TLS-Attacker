/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

public class CrlReason {
    private static final BiMap<Integer, String> reasonMap = HashBiMap.create();

    static {
        reasonMap.put(0, "unspecified");
        reasonMap.put(1, "keyCompromise");
        reasonMap.put(2, "cACompromise");
        reasonMap.put(3, "affiliationChanged");
        reasonMap.put(4, "superseded");
        reasonMap.put(5, "cessationOfOperation");
        reasonMap.put(6, "certificateHold");
        // case 7 is undefined by standard
        reasonMap.put(8, "removeFromCRL");
        reasonMap.put(9, "privilegeWithdrawn");
        reasonMap.put(10, "aACompromise");
    }

    public static String translate(Integer input) {
        String translated;
        translated = reasonMap.get(input);
        return translated;
    }

    public static Integer translate(String input) {
        Integer translated;
        translated = reasonMap.inverse().get(input);
        return translated;
    }
}
