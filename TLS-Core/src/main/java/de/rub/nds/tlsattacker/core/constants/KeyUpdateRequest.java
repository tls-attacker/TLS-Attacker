/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

public enum KeyUpdateRequest {

    UPDATE_NOT_REQUESTED((byte) 0),
    UPDATE_REQUESTED((byte) 1);

    private byte value;

    private KeyUpdateRequest(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }
}
