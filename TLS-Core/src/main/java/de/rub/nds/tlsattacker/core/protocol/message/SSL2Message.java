/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlTransient;

// TODO: this should be "Self extends SSL2Message". However, this would require a parser for the
// UnknownSSL2Message.
@SuppressWarnings("serial")
public abstract class SSL2Message<Self extends ProtocolMessage<?>> extends ProtocolMessage<Self> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;

    // Number of padding bytes for payloads encrypted with a block cipher (not
    // to be mistaken with PKCS#1 padding)
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger paddingLength;

    /** message type */
    private ModifiableByte type = null;

    @XmlTransient private SSL2MessageType ssl2MessageType;

    public SSL2Message(SSL2MessageType ssl2MessageType) {
        this.ssl2MessageType = ssl2MessageType;
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(Integer messageLength) {
        this.messageLength =
                ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableInteger getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(Integer paddingLength) {
        this.paddingLength =
                ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        if (getType() != null && getType().getValue() != null) {
            sb.append("\n Type: ").append(getType().getValue());
        }
        return sb.toString();
    }

    public ModifiableByte getType() {
        return type;
    }

    public void setType(ModifiableByte type) {
        this.type = type;
    }

    public void setType(Byte type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public SSL2MessageType getSsl2MessageType() {
        return ssl2MessageType;
    }

    public void setSsl2MessageType(SSL2MessageType ssl2MessageType) {
        this.ssl2MessageType = ssl2MessageType;
    }
}
