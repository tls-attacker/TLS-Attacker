/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.stun.StunContext;

public abstract class StunAttribute extends ModifiableVariableHolder
        implements DataContainer<StunContext> {

    /** 2 bytes */
    private ModifiableByteArray attributeType;

    /** 2 bytes */
    private ModifiableInteger attributeLength;

    private ModifiableByte padding;

    public StunAttribute() {}

    public ModifiableByteArray getAttributeType() {
        return attributeType;
    }

    public void setAttributeType(ModifiableByteArray attributeType) {
        this.attributeType = attributeType;
    }

    public ModifiableInteger getAttributeLength() {
        return attributeLength;
    }

    public void setAttributeLength(ModifiableInteger attributeLength) {
        this.attributeLength = attributeLength;
    }

    public void setAttributeType(byte[] attributeType) {
        this.attributeType =
                ModifiableVariableFactory.safelySetValue(this.attributeType, attributeType);
    }

    public ModifiableByte getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByte padding) {
        this.padding = padding;
    }

    public void setPadding(byte padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }
}
