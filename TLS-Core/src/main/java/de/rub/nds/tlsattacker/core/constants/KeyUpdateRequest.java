/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;

public enum KeyUpdateRequest {

    UPDATE_NOT_REQUESTED((byte) 0),
    UPDATE_REQUESTED((byte) 1);

    private ModifiableByte requestUpdate;

    private KeyUpdateRequest(byte requestUpdate) {
        this.requestUpdate = ModifiableVariableFactory.safelySetValue(this.requestUpdate, requestUpdate);
    }

    public byte getValue() {
        return requestUpdate.getValue();
    }

}
