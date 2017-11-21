/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EarlyDataExtensionMessage extends ExtensionMessage {

    private ModifiableInteger maxEarlyDataSize;

    public EarlyDataExtensionMessage() {
        super(ExtensionType.EARLY_DATA);
    }

    /**
     * @return the max_early_data_size
     */
    public ModifiableInteger getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }

    /**
     * @param maxEarlyDataSize
     *            the maxEarlyDataSize to set
     */
    public void setMaxEarlyDataSize(ModifiableInteger maxEarlyDataSize) {
        this.maxEarlyDataSize = maxEarlyDataSize;
    }

    public void setMaxEarlyDataSize(int maxEarlyDataSize) {
        this.maxEarlyDataSize = ModifiableVariableFactory.safelySetValue(this.maxEarlyDataSize, maxEarlyDataSize);
    }
}
