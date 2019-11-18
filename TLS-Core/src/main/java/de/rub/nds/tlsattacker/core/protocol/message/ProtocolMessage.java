/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Random;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

/**
 * TLS Protocol message is the message included in the Record message.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ProtocolMessage extends ModifiableVariableHolder {

    /**
     * content type
     */
    @XmlTransient
    protected ProtocolMessageType protocolMessageType;

    @XmlTransient
    protected boolean GOING_TO_BE_SENT_DEFAULT = true;

    @XmlTransient
    protected boolean REQUIRED_DEFAULT = true;

    @XmlTransient
    protected boolean ADJUST_CONTEXT_DEFAULT = true;

    /**
     * Defines whether this message is necessarily required in the workflow.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this
     * flag it is possible to omit a message is sent during the handshake while
     * it is executed to initialize specific variables.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean goingToBeSent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean adjustContext;

    /**
     * resulting message
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;

    public ProtocolMessage() {
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    public boolean isRequired() {
        if (required == null || required.getValue() == null) {
            return REQUIRED_DEFAULT;
        }
        return required.getValue();
    }

    public void setRequired(boolean required) {
        this.required = ModifiableVariableFactory.safelySetValue(this.required, required);
    }

    public boolean isGoingToBeSent() {
        if (goingToBeSent == null || goingToBeSent.getValue() == null) {
            return GOING_TO_BE_SENT_DEFAULT;
        }
        return goingToBeSent.getValue();
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent = ModifiableVariableFactory.safelySetValue(this.goingToBeSent, goingToBeSent);
    }

    public void setGoingToBeSent(ModifiableBoolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        return holders;
    }

    @Override
    public Field getRandomModifiableVariableField(Random random) {
        List<Field> fields = getAllModifiableVariableFields();
        int randomField = random.nextInt(fields.size());
        return fields.get(randomField);
    }

    public ModifiableByteArray getCompleteResultingMessage() {
        return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
        this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
        this.completeResultingMessage = ModifiableVariableFactory.safelySetValue(this.completeResultingMessage,
                completeResultingMessage);
    }

    public boolean getAdjustContext() {
        if (adjustContext == null || adjustContext.getValue() == null) {
            return ADJUST_CONTEXT_DEFAULT;
        }
        return adjustContext.getValue();
    }

    public void setAdjustContext(ModifiableBoolean adjustContext) {
        this.adjustContext = adjustContext;
    }

    public void setAdjustContext(Boolean adjustContext) {
        this.adjustContext = ModifiableVariableFactory.safelySetValue(this.adjustContext, adjustContext);
    }

    public boolean isHandshakeMessage() {
        return this instanceof HandshakeMessage;
    }

    public boolean isDtlsHandshakeMessageFragment() {
        return this instanceof DtlsHandshakeMessageFragment;
    }

    public abstract String toCompactString();

    public abstract ProtocolMessageHandler getHandler(TlsContext context);
}
