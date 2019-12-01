/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.esni;

import java.io.Serializable;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;

public class PublicKeyShareEntry extends ModifiableVariableHolder implements Serializable {
    @ModifiableVariableProperty
    private ModifiableByteArray namedGroup;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger keyExchangeLength;

    @ModifiableVariableProperty
    private ModifiableByteArray keyExchange;

    public ModifiableByteArray getNamedGroup() {
        return namedGroup;
    }

    public void setNamedGroup(ModifiableByteArray namedGroup) {
        this.namedGroup = namedGroup;
    }

    public void setNamedGroup(byte[] bytes) {
        this.namedGroup = ModifiableVariableFactory.safelySetValue(namedGroup, bytes);
    }

    public ModifiableInteger getKeyExchangeLength() {
        return keyExchangeLength;
    }

    public void setKeyExchangeLength(ModifiableInteger keyExchangeLength) {
        this.keyExchangeLength = keyExchangeLength;
    }

    public void setKeyExchangeLength(int length) {
        this.keyExchangeLength = ModifiableVariableFactory.safelySetValue(keyExchangeLength, length);
    }

    public ModifiableByteArray getKeyExchange() {
        return keyExchange;
    }

    public void setKeyExchange(ModifiableByteArray keyExchange) {
        this.keyExchange = keyExchange;
    }

    public void setKeyExchange(byte[] bytes) {
        this.keyExchange = ModifiableVariableFactory.safelySetValue(keyExchange, bytes);
    }

}
