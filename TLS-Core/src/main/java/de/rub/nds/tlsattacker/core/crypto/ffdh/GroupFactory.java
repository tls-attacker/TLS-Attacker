/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.ffdh;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;

public class GroupFactory {
    public static FFDHEGroup getGroup(NamedGroup group) {
        switch (group) {
            case FFDHE2048:
                return new GroupFFDHE2048();
            case FFDHE3072:
                return new GroupFFDHE3072();
            case FFDHE4096:
                return new GroupFFDHE4096();
            case FFDHE6144:
                return new GroupFFDHE6144();
            case FFDHE8192:
                return new GroupFFDHE8192();
            default:
                throw new UnsupportedOperationException(
                    "The provided group '" + group + "' is not supported by this method.");
        }
    }
}
