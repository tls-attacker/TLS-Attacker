/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public enum FiniteFieldGroups {
    ffdhe2048(new byte[]{01, 00}), ffdhe3072(new byte[]{01, 01}), ffdhe4096(new byte[]{01, 02}),
    ffdhe6144(new byte[]{01, 03}), ffdhe8192(new byte[]{01, 04});

    private final byte[] value;

    private FiniteFieldGroups(byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }
}
