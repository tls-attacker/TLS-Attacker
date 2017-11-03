/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.SupplementalData;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

/**
 * @author Christoph Penkert <christoph.penkert@rub.de>
 */

public class SupplementalDataEntry {

    @ModifiableVariableProperty
    private ModifiableByteArray supplementalData;

    @ModifiableVariableProperty
    private ModifiableInteger supplementalDataType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supplementalDataLength;

    public SupplementalDataEntry(int supplementalDataType, int supplementalDataLength, byte[] supplementalData) {
        this.supplementalDataType = ModifiableVariableFactory.safelySetValue(this.supplementalDataType,
                supplementalDataType);
        this.supplementalDataLength = ModifiableVariableFactory.safelySetValue(this.supplementalDataLength,
                supplementalDataLength);
        this.supplementalData = ModifiableVariableFactory.safelySetValue(this.supplementalData, supplementalData);

    }

    public ModifiableByteArray getSupplementalData() {
        return this.supplementalData;
    }

    public void setSupplementalData(ModifiableByteArray supplementalData) {
        this.supplementalData = supplementalData;
    }

    public void setSupplementalData(byte[] supplementalData) {
        this.supplementalData = ModifiableVariableFactory.safelySetValue(this.supplementalData, supplementalData);
    }

    public ModifiableInteger getSupplementalDataType() {
        return supplementalDataType;
    }

    public void setSupplementalDataType(ModifiableInteger supplementalDataType) {
        this.supplementalDataType = supplementalDataType;
    }

    public void setSupplementalDataType(int supplementalDataType) {
        this.supplementalDataType = ModifiableVariableFactory.safelySetValue(this.supplementalDataType,
                supplementalDataType);
    }

    public ModifiableInteger getSupplementalDataLength() {
        return supplementalDataLength;
    }

    public void setSupplementalDataLength(ModifiableInteger supplementalDataLength) {
        this.supplementalDataLength = supplementalDataLength;
    }

    public void setSupplementalDataLength(int supplementalDataLength) {
        this.supplementalDataLength = ModifiableVariableFactory.safelySetValue(this.supplementalDataLength,
                supplementalDataLength);
    }

}
