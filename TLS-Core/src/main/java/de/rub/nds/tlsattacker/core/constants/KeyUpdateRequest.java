/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;

public enum KeyUpdateRequest {

    UPDATE_NOT_REQUESTED((byte) 0),
    UPDATE_REQUESTED((byte) 1);

    @HoldsModifiableVariable
    private byte request_update;

    private KeyUpdateRequest(byte request_update) {
        this.request_update = request_update;
    }

    public byte getValue() {
        return request_update;
    }

}
