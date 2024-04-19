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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;

public class ErrorCodeAttribute {

    private ModifiableByteArray reservedByte;

    private ModifiableInteger number;

    private ModifiableString reasonPhrase;

    public ErrorCodeAttribute() {}

    public ModifiableByteArray getReservedByte() {
        return reservedByte;
    }

    public void setReservedByte(ModifiableByteArray reservedByte) {
        this.reservedByte = reservedByte;
    }

    public ModifiableInteger getNumber() {
        return number;
    }

    public void setNumber(ModifiableInteger number) {
        this.number = number;
    }

    public ModifiableString getReasonPhrase() {
        return reasonPhrase;
    }

    public void setReasonPhrase(ModifiableString reasonPhrase) {
        this.reasonPhrase = reasonPhrase;
    }

    public void setReasonPhrase(String reasonPhrase) {
        this.reasonPhrase =
                ModifiableVariableFactory.safelySetValue(this.reasonPhrase, reasonPhrase);
    }

    public void setNumber(int number) {
        this.number = ModifiableVariableFactory.safelySetValue(this.number, number);
    }

    public void setReservedByte(byte[] reservedByte) {
        this.reservedByte =
                ModifiableVariableFactory.safelySetValue(this.reservedByte, reservedByte);
    }
}
