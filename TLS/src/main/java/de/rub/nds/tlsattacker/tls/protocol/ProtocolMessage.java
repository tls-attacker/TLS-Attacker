/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
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
 */
@XmlRootElement
public abstract class ProtocolMessage extends ModifiableVariableHolder implements ProtocolMessageHandlerBearer,
	Serializable {

    /**
     * content type
     */
    protected ProtocolMessageType protocolMessageType;

    /**
     * describes if the messages are coming from the client or the server.
     */
    protected ConnectionEnd messageIssuer;

    /**
     * List of preconfigured records for this protocol message
     */
    protected List<Record> records;

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

    @Override
    public abstract ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext);

    public ProtocolMessageType getProtocolMessageType() {
	return protocolMessageType;
    }

    public ConnectionEnd getMessageIssuer() {
	return messageIssuer;
    }

    public void setMessageIssuer(ConnectionEnd messageIssuer) {
	this.messageIssuer = messageIssuer;
    }

    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "record") })
    public List<Record> getRecords() {
	return records;
    }

    public void setRecords(List<Record> records) {
	this.records = records;
    }

    public void addRecord(Record record) {
	if (this.records == null) {
	    this.records = new LinkedList<>();
	}
	this.records.add(record);
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

}
