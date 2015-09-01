/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested
 * server is vulnerable to poodle.
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class PaddingOracleAttack extends Attacker<PaddingOracleCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(PaddingOracleAttack.class);

    private List<ProtocolMessage> lastMessages;

    public PaddingOracleAttack(PaddingOracleCommandConfig config) {
	super(config);
	lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	List<Record> records = new LinkedList<>();
	records.addAll(createRecordsWithPlainData());
	records.addAll(createRecordsWithModifiedMac());
	records.addAll(createRecordsWithModifiedPadding());

	for (Record record : records) {
	    executeAttackRound(configHandler, record);
	}

	LOGGER.info("All the attack runs executed. The following messages arrived at the ends of the connections");
	LOGGER.info("If there are different messages, this could indicate the server does not process padding correctly");

	for (ProtocolMessage pm : lastMessages) {
	    LOGGER.info(pm.toString());
	}
    }

    public void executeAttackRound(ConfigHandler configHandler, Record record) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ApplicationMessage applicationMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	applicationMessage.addRecord(record);

	AlertMessage allertMessage = new AlertMessage(ConnectionEnd.SERVER);

	trace.getProtocolMessages().add(applicationMessage);
	trace.getProtocolMessages().add(allertMessage);

	workflowExecutor.executeWorkflow();

	lastMessages.add(trace.getLastProtocolMesssage());

	transportHandler.closeConnection();
    }

    private List<Record> createRecordsWithPlainData() {
	List<Record> records = new LinkedList();
	for (int i = 0; i < 64; i++) {
	    byte[] padding = createPaddingBytes(i);
	    int messageSize = config.getBlockSize() - (padding.length % config.getBlockSize());
	    byte[] message = new byte[messageSize];
	    byte[] plain = ArrayConverter.concatenate(message, padding);
	    Record r = createRecordWithPlainData(plain);
	    records.add(r);
	}
	Record r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255 });
	records.add(r);
	r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255 });
	records.add(r);
	return records;
    }

    private Record createRecordWithPlainData(byte[] plain) {
	Record r = new Record();
	ModifiableByteArray plainData = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
	plainData.setModification(modifier);
	r.setPlainRecordBytes(plainData);
	return r;
    }

    private List<Record> createRecordsWithModifiedPadding() {
	List<Record> records = new LinkedList();

	Record r = new Record();
	ModifiableByteArray padding = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
	padding.setModification(modifier);
	r.setPadding(padding);
	records.add(r);

	return records;
    }

    private List<Record> createRecordsWithModifiedMac() {
	List<Record> records = new LinkedList();

	Record r = new Record();
	ModifiableByteArray mac = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1, 1, 1 }, 0);
	mac.setModification(modifier);
	r.setMac(mac);
	records.add(r);

	return records;
    }

    private byte[] createPaddingBytes(int padding) {
	byte[] paddingBytes = new byte[padding + 1];
	for (int i = 0; i < paddingBytes.length; i++) {
	    paddingBytes[i] = (byte) padding;
	}
	return paddingBytes;
    }

}
