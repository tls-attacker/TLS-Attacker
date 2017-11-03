/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;

public class StringHelper {
    public static <E extends Enum<E>> String enumToString(Class<E> e) {
        return join(EnumSet.allOf(e));
    }

    public static String join(Object[] objects) {
        return join(Arrays.asList(objects));
    }

    public static String join(Collection collection) {
        StringBuilder sb = new StringBuilder();
        for (Object o : collection) {
            sb.append(o.toString()).append(System.lineSeparator());
        }
        sb.deleteCharAt(sb.lastIndexOf(System.lineSeparator()));
        return sb.toString();
    }
}
