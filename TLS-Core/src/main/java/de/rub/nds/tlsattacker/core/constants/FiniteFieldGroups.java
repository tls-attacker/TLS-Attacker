/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum FiniteFieldGroups {
    FFDHE2048(new byte[] { 01, 00 }),
    FFDHE3072(new byte[] { 01, 01 }),
    FFDHE4096(new byte[] { 01, 02 }),
    FFDHE6144(new byte[] { 01, 03 }),
    FFDHE8192(new byte[] { 01, 04 });

    private final byte[] value;

    private FiniteFieldGroups(byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }
}
