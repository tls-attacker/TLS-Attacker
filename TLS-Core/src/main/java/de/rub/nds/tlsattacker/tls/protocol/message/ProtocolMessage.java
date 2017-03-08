/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.dtls.record.DtlsRecord;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * TLS Protocol message is the message included in the Record message.
 *
 * @author juraj
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlRootElement
public abstract class ProtocolMessage extends ModifiableVariableHolder implements Serializable {

    /**
     * content type
     */
    protected ProtocolMessageType protocolMessageType;

    /**
     * List of preconfigured records for this protocol message
     */
    protected List<Record> records;

    /**
     * Defines whether this message is necessarily required in the workflow.
     */
    private boolean required = true;
    /**
     * Defines if the message should be sent during the workflow. Using this
     * flag it is possible to omit a message is sent during the handshake while
     * it is executed to initialize specific variables.
     */
    private boolean goingToBeSent = true;
    /**
     * resulting message
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;

    public ProtocolMessage() {
        records = new LinkedList<>();
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    @XmlElementWrapper
    @XmlElements(value = {
        @XmlElement(type = Record.class, name = "Record")
        ,
            @XmlElement(type = DtlsRecord.class, name = "DtlsRecord")})
    public List<Record> getRecords() {
        return records;
    }

    public void setRecords(List<Record> records) {
        this.records = records;
    }

    public void addRecord(Record record) {
        this.records.add(record);
    }

    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public boolean isGoingToBeSent() {
        return goingToBeSent;
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (records != null) {
            for (Record r : records) {
                holders.add(r);
            }
        }
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

    public abstract String toCompactString();

    public abstract Serializer getSerializer();
}
