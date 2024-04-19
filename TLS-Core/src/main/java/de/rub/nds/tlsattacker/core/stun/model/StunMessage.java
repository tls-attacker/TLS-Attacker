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

public abstract class StunMessage {

    /** 2 bytes */
    private ModifiableByteArray stunMessageType;

    /** 2 bytes */
    private ModifiableInteger messageLength;

    /** 4 bytes */
    private ModifiableByteArray magicCookie;

    /** 12 bytes */
    private ModifiableByteArray transactionId;

    private StunMessage() {}

    public ModifiableByteArray getStunMessageType() {
        return stunMessageType;
    }

    public void setStunMessageType(ModifiableByteArray stunMessageType) {
        this.stunMessageType = stunMessageType;
    }

    public void setStunMessageType(byte[] stunMessageType) {
        this.stunMessageType =
                ModifiableVariableFactory.safelySetValue(this.stunMessageType, stunMessageType);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public ModifiableByteArray getMagicCookie() {
        return magicCookie;
    }

    public void setMagicCookie(ModifiableByteArray magicCookie) {
        this.magicCookie = magicCookie;
    }

    public ModifiableByteArray getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(ModifiableByteArray transactionId) {
        this.transactionId = transactionId;
    }
}
