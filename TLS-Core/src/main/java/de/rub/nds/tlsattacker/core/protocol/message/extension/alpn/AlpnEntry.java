/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.alpn;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

public class AlpnEntry extends ModifiableVariableHolder implements Serializable {

    private ModifiableInteger alpnEntryLength;

    private ModifiableByteArray alpnEntryBytes;

    private byte[] alpnEntryConfig;

    public AlpnEntry() {
    }

    public AlpnEntry(byte[] alpnEntryConfig) {
        this.alpnEntryConfig = alpnEntryConfig;
    }

    public ModifiableInteger getAlpnEntryLength() {
        return alpnEntryLength;
    }

    public void setAlpnEntryLength(ModifiableInteger alpnEntryLength) {
        this.alpnEntryLength = alpnEntryLength;
    }

    public void setAlpnEntryLength(int alpnEntryLength) {
        this.alpnEntryLength = ModifiableVariableFactory.safelySetValue(this.alpnEntryLength, alpnEntryLength);
    }

    public ModifiableByteArray getAlpnEntryBytes() {
        return alpnEntryBytes;
    }

    public void setAlpnEntryBytes(ModifiableByteArray alpnEntryBytes) {
        this.alpnEntryBytes = alpnEntryBytes;
    }

    public void setAlpnEntryBytes(byte[] alpnEntryBytes) {
        this.alpnEntryBytes = ModifiableVariableFactory.safelySetValue(this.alpnEntryBytes, alpnEntryBytes);
    }

    public byte[] getAlpnEntryConfig() {
        return alpnEntryConfig;
    }

    public void setAlpnEntryConfig(byte[] alpnEntryConfig) {
        this.alpnEntryConfig = alpnEntryConfig;
    }
}
