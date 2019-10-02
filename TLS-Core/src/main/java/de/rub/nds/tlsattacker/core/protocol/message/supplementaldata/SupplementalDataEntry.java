/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.supplementaldata;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

public class SupplementalDataEntry {

    @ModifiableVariableProperty
    private ModifiableByteArray supplementalDataEntry;

    @ModifiableVariableProperty
    private ModifiableInteger supplementalDataEntryType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supplementalDataEntryLength;

    public SupplementalDataEntry() {

    }

    public ModifiableByteArray getSupplementalDataEntry() {
        return this.supplementalDataEntry;
    }

    public void setSupplementalDataEntry(ModifiableByteArray supplementalDataEntry) {
        this.supplementalDataEntry = supplementalDataEntry;
    }

    public void setSupplementalDataEntry(byte[] supplementalDataEntry) {
        this.supplementalDataEntry = ModifiableVariableFactory.safelySetValue(this.supplementalDataEntry,
                supplementalDataEntry);
    }

    public ModifiableInteger getSupplementalDataEntryType() {
        return supplementalDataEntryType;
    }

    public void setSupplementalDataEntryType(ModifiableInteger supplementalDataEntryType) {
        this.supplementalDataEntryType = supplementalDataEntryType;
    }

    public void setSupplementalDataEntryType(int supplementalDataEntryType) {
        this.supplementalDataEntryType = ModifiableVariableFactory.safelySetValue(this.supplementalDataEntryType,
                supplementalDataEntryType);
    }

    public ModifiableInteger getSupplementalDataEntryLength() {
        return supplementalDataEntryLength;
    }

    public void setSupplementalDataEntryLength(ModifiableInteger supplementalDataEntryLength) {
        this.supplementalDataEntryLength = supplementalDataEntryLength;
    }

    public void setSupplementalDataEntryLength(int supplementalDataEntryLength) {
        this.supplementalDataEntryLength = ModifiableVariableFactory.safelySetValue(this.supplementalDataEntryLength,
                supplementalDataEntryLength);
    }

}
