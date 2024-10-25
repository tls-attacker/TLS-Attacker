/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ProtocolMessage extends Message<TlsContext> {

    @XmlTransient protected boolean goingToBeSentDefault = true;
    @XmlTransient protected boolean requiredDefault = true;
    @XmlTransient protected boolean adjustContextDefault = true;
    @XmlTransient protected boolean shouldPrepareDefault = true;
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

    public boolean isHandshakeMessage() {
        return this instanceof HandshakeMessage;
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    @Override
    public abstract ProtocolMessageHandler<? extends ProtocolMessage> getHandler(
            TlsContext context);

    @Override
    public abstract ProtocolMessageParser<? extends ProtocolMessage> getParser(
            TlsContext context, InputStream stream);

    @Override
    public abstract ProtocolMessagePreparator<? extends ProtocolMessage> getPreparator(
            TlsContext context);

    @Override
    public abstract ProtocolMessageSerializer<? extends ProtocolMessage> getSerializer(
            TlsContext context);
}
