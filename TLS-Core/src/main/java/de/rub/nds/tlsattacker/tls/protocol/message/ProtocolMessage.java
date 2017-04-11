/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * TLS Protocol message is the message included in the Record message.
 *
 * @author juraj
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ProtocolMessage extends ModifiableVariableHolder implements Serializable {

    /**
     * content type
     */
    @XmlTransient
    protected ProtocolMessageType protocolMessageType;

    private static final boolean GOING_TO_BE_SENT_DEFAULT = true;

    private static final boolean REQUIRED_DEFAULT = true;
    /**
     * Defines whether this message is necessarily required in the workflow.
     */
    private Boolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this
     * flag it is possible to omit a message is sent during the handshake while
     * it is executed to initialize specific variables.
     */

    private Boolean goingToBeSent;
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
        if (required == null) {
            return REQUIRED_DEFAULT;
        }
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public boolean isGoingToBeSent() {
        if (goingToBeSent == null) {
            return GOING_TO_BE_SENT_DEFAULT;
        }
        return goingToBeSent;
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        return holders;
    }

    @Override
    public Field getRandomModifiableVariableField() {
        List<Field> fields = getAllModifiableVariableFields();
        int randomField = RandomHelper.getRandom().nextInt(fields.size());
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

    public boolean isHandshakeMessage() {
        return this instanceof HandshakeMessage;
    }

    @Override
    public String toString() {
        return toCompactString();
    }

    public abstract String toCompactString();

    public abstract ProtocolMessageHandler getHandler(TlsContext context);
}
