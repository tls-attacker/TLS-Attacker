/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.psk;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

public class PSKBinder extends ModifiableVariableHolder implements Serializable {

    private CipherSuite binderCipherConfig;

    private ModifiableInteger binderEntryLength;
    private ModifiableByteArray binderEntry;

    public PSKBinder() {}

    public void setBinderEntry(ModifiableByteArray binderEntry) {
        this.binderEntry = binderEntry;
    }

    public void setBinderEntry(byte[] binderEntry) {
        this.binderEntry = ModifiableVariableFactory.safelySetValue(this.binderEntry, binderEntry);
    }

    public ModifiableByteArray getBinderEntry() {
        return binderEntry;
    }

    public void setBinderEntryLength(ModifiableInteger binderEntryLength) {
        this.binderEntryLength = binderEntryLength;
    }

    public void setBinderEntryLength(int binderEntryLength) {
        this.binderEntryLength =
                ModifiableVariableFactory.safelySetValue(this.binderEntryLength, binderEntryLength);
    }

    public ModifiableInteger getBinderEntryLength() {
        return binderEntryLength;
    }

    /**
     * @return the binderCipherConfig
     */
    public CipherSuite getBinderCipherConfig() {
        return binderCipherConfig;
    }

    /**
     * @param binderCipherConfig the binderCipherConfig to set
     */
    public void setBinderCipherConfig(CipherSuite binderCipherConfig) {
        this.binderCipherConfig = binderCipherConfig;
    }
}
