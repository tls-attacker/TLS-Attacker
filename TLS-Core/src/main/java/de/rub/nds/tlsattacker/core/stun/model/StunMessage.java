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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

import java.util.LinkedList;
import java.util.List;

public abstract class StunMessage extends Message<IceContext> {

    /** 2 bytes */
    private ModifiableByteArray stunMessageType;

    /** 2 bytes */
    private ModifiableInteger messageLength;

    /** 4 bytes */
    private ModifiableBoolean magicCookiePresent;

    /** 12 bytes */
    private ModifiableByteArray transactionId;

    private List<StunAttribute> attributeList;

    private StunMessage() {
        attributeList = new LinkedList<>();
    }

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

    public void setMessageLength(int messageLength) {
        this.messageLength =
                ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableBoolean getMagicCookiePresent() {
        return magicCookiePresent;
    }

    public void setMagicCookiePresent(ModifiableBoolean magicCookiePresent) {
        this.magicCookiePresent = magicCookiePresent;
    }

    public void setMagicCookiePresent(boolean magicCookiePresent) {
        this.magicCookiePresent =
                ModifiableVariableFactory.safelySetValue(
                        this.magicCookiePresent, magicCookiePresent);
    }

    public ModifiableByteArray getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(ModifiableByteArray transactionId) {
        this.transactionId = transactionId;
    }

    public void setTransactionId(byte[] transactionId) {
        this.transactionId =
                ModifiableVariableFactory.safelySetValue(this.transactionId, transactionId);
    }

    public List<StunAttribute> getAttributeList() {
        return attributeList;
    }

    public void setAttributeList(List<StunAttribute> attributeList) {
        this.attributeList = attributeList;
    }
}
