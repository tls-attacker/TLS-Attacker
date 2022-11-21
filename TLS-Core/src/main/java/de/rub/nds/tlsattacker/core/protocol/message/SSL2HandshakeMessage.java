/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;

@SuppressWarnings("serial")
public abstract class SSL2HandshakeMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;

    // Number of padding bytes for payloads encrypted with a block cipher (not
    // to be mistaken with PKCS#1 padding)
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger paddingLength;

    public SSL2HandshakeMessage(HandshakeMessageType handshakeMessageType) {
        super(handshakeMessageType);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(Integer messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableInteger getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(Integer paddingLength) {
        this.paddingLength = ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        if (getType() != null && getType().getValue() != null) {
            sb.append("\n Type: ").append(getType().getValue());
        }
        return sb.toString();
    }
}