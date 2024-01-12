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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2MessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2MessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2MessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2MessageSerializer;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;
import java.util.List;

public abstract class SSL2Message extends Message<TlsContext> {

    @XmlTransient protected boolean goingToBeSentDefault = true;
    @XmlTransient protected boolean requiredDefault = true;
    @XmlTransient protected boolean adjustContextDefault = true;
    @XmlTransient protected boolean shouldPrepareDefault = true;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;

    // Number of padding bytes for payloads encrypted with a block cipher (not
    // to be mistaken with PKCS#1 padding)
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger paddingLength;

    /** resulting message */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;
    /** Defines whether this message is necessarily required in the workflow. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this flag it is possible to
     * omit a message is sent during the handshake while it is executed to initialize specific
     * variables.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean goingToBeSent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean adjustContext;

    /** content type */
    @XmlTransient protected ProtocolMessageType protocolMessageType;

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

    public boolean addToTypes(List<ProtocolMessageType> protocolMessageTypes) {
        return protocolMessageTypes.add(getProtocolMessageType());
    }

    public void setShouldPrepareDefault(boolean shouldPrepare) {
        this.shouldPrepareDefault = shouldPrepare;
    }

    @Override
    public boolean shouldPrepare() {
        return shouldPrepareDefault;
    }

    @Override
    public boolean isRequired() {
        if (required == null || required.getValue() == null) {
            return requiredDefault;
        }
        return required.getValue();
    }

    public void setRequired(boolean required) {
        this.required = ModifiableVariableFactory.safelySetValue(this.required, required);
    }

    public boolean isGoingToBeSent() {
        if (goingToBeSent == null || goingToBeSent.getValue() == null) {
            return goingToBeSentDefault;
        }
        return goingToBeSent.getValue();
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent =
                ModifiableVariableFactory.safelySetValue(this.goingToBeSent, goingToBeSent);
    }

    public void setGoingToBeSent(ModifiableBoolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    public ModifiableByteArray getCompleteResultingMessage() {
        return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
        this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
        this.completeResultingMessage =
                ModifiableVariableFactory.safelySetValue(
                        this.completeResultingMessage, completeResultingMessage);
    }

    public boolean getAdjustContext() {
        if (adjustContext == null || adjustContext.getValue() == null) {
            return adjustContextDefault;
        }
        return adjustContext.getValue();
    }

    public void setAdjustContext(ModifiableBoolean adjustContext) {
        this.adjustContext = adjustContext;
    }

    public void setAdjustContext(Boolean adjustContext) {
        this.adjustContext =
                ModifiableVariableFactory.safelySetValue(this.adjustContext, adjustContext);
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    @Override
    public abstract SSL2MessageHandler<? extends SSL2Message> getHandler(TlsContext context);

    @Override
    public abstract SSL2MessageParser<? extends SSL2Message> getParser(
            TlsContext context, InputStream stream);

    @Override
    public abstract SSL2MessagePreparator<? extends SSL2Message> getPreparator(TlsContext context);

    @Override
    public abstract SSL2MessageSerializer<? extends SSL2Message> getSerializer(TlsContext context);
}
