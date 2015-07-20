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
package de.rub.nds.tlsattacker.dtls.workflow;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields.HandshakeMessageDtlsFields;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.dtls.record.handlers.RecordHandler;
import de.rub.nds.tlsattacker.dtls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.exceptions.MalformedMessageException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class Dtls12WorkflowExecutor implements WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(Dtls12WorkflowExecutor.class);

    /**
     * indicates if the workflow was already executed
     */
    private boolean executed = false;

    /**
     * indicates that an unexpected message was found during the workflow
     * execution
     */
    private boolean unexpectedMessageFound = false;

    private final RecordHandler recordHandler;

    private final TlsContext tlsContext;

    private final WorkflowTrace workflowTrace;

    private final TransportHandler transportHandler;

    private byte[] dataToSend;

    private int maxFlightRetries = 4;

    private List<ProtocolMessage> protocolMessages;

    private int protocolMessagePointer, recordContentBufferOffset, messageFlightPointer, flightStartMessageNumber,
	    expectedHandshakeMessageSeq, sendHandshakeMessageSeq, epochCounter, flightRetransmitCounter;

    private Record currentRecord;

    private int maxHandshakeReorderBufferSize = 100;

    private int maxPacketSize = 1400;

    private int previousFlightBeginPointer = -1;

    private List<de.rub.nds.tlsattacker.tls.record.messages.Record> recordBuffer = new LinkedList<>();

    private final Map<Integer, List<Record>> handshakeMessageRecordMap = new HashMap<>();

    private final Map<Integer, BitSet> handshakeMessageReassembleBitmaskMap = new HashMap<>();

    private final Map<Integer, byte[]> reassembledHandshakeMessageMap = new HashMap<>();

    private byte[] recordContentBuffer = new byte[0];

    private ProtocolMessageType currentProtocolMessageType = ProtocolMessageType.ALERT;

    private ConnectionEnd lastConnectionEnd;

    private ConnectionEnd previousFlightConnectionEnd;

    private int maxWaitForExpectedRecord = 3000;

    private boolean expectingChangeChipherSpec = false;

    private Record changeCipherSpecRecord;

    private boolean wholeRecordParsedPreviously;

    private byte[] digestBytesBeforeNextFlightBegin = new byte[0];

    private boolean fatalAlertMessageFound = false;

    private byte[] handshakeMessageSendBuffer;

    private List<de.rub.nds.tlsattacker.tls.record.messages.Record> handshakeMessageSendRecordList = null;

    private byte[] recordSendBuffer = new byte[0];

    public Dtls12WorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	this.tlsContext = tlsContext;
	this.workflowTrace = this.tlsContext.getWorkflowTrace();
	this.transportHandler = transportHandler;
	this.recordHandler = RecordHandler.createInstance(tlsContext);
	if (this.transportHandler == null || this.recordHandler == null) {
	    throw new ConfigurationException("The WorkflowExecutor was not configured properly");
	}
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
	if (executed) {
	    throw new IllegalStateException("The workflow has already been executed. Create a new Workflow.");
	}
	executed = true;

	lastConnectionEnd = null;
	protocolMessages = workflowTrace.getProtocolMessages();
	protocolMessagePointer = 0;
	try {
	    ProtocolMessage pm;
	    boolean proceedWorkflow = true;

	    while ((protocolMessagePointer < protocolMessages.size()) && proceedWorkflow
		    && (flightRetransmitCounter <= maxFlightRetries)) {
		pm = getNextWorkflowProtocolMessage();
		updateFlight(pm);
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
		    sendNextProtocolMessage(pm);
		} else {
		    proceedWorkflow = !receiveAndParseNextProtocolMessage(pm);
		}
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	    protocolMessagePointer--;
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	} finally {
	    // remove all unused protocol messages
	    this.removeNextProtocolMessages(protocolMessages, protocolMessagePointer + 1);
	}
    }

    private void sendNextProtocolMessage(ProtocolMessage pm) throws IOException {
	LOGGER.debug("Preparing the following protocol message to send: {}", pm.getClass());

	if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
	    sendHandshakeMessage((HandshakeMessage) pm);
	} else if (pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
	    sendChangeCipherSpecMessage(pm);
	} else {
	    sendNonHandshakeMessage(pm);
	}
    }

    private void sendNonHandshakeMessage(ProtocolMessage protocolMessage) throws IOException {
	byte[] messageBytes = protocolMessage.getCompleteResultingMessage().getValue();

	if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
	    protocolMessage.addRecord(new Record());
	}

	byte[] record = recordHandler.wrapData(messageBytes, protocolMessage.getProtocolMessageType(),
		protocolMessage.getRecords());

	LOGGER.debug("Sending the following protocol message to TLS peer: {}\nRaw Bytes: {}",
		protocolMessage.getClass(), ArrayConverter.bytesToHexString(record));

	if (protocolMessage.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
	    sendMessages(record);
	} else {
	    transportHandler.sendData(record);
	}
    }

    private void sendChangeCipherSpecMessage(ProtocolMessage protocolMessage) throws IOException {
	ProtocolMessageHandler pmh = protocolMessage.getProtocolMessageHandler(tlsContext);
	byte[] messageBytes = pmh.prepareMessage();

	// retransmitBuffer = ArrayConverter.concatenate(retransmitBuffer,
	// messageBytes);

	if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
	    protocolMessage.addRecord(new Record());
	}

	byte[] record = recordHandler.wrapData(messageBytes, ProtocolMessageType.CHANGE_CIPHER_SPEC,
		protocolMessage.getRecords());

	sendMessages(record);
    }

    private void sendHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
	int maxMessageSize = maxPacketSize - 25;

	ProtocolMessageHandler pmh = handshakeMessage.getProtocolMessageHandler(tlsContext);
	HandshakeMessageDtlsFields handshakeMessageFields = (HandshakeMessageDtlsFields) handshakeMessage
		.getMessageFields();
	handshakeMessageFields.setMessageSeq(sendHandshakeMessageSeq);
	handshakeMessageFields.setFragmentOffset(0);
	byte[] handshakeMessageBytes = pmh.prepareMessage();
	int handshakeMessageContentLength = handshakeMessageBytes.length - 12;

	if (handshakeMessageContentLength > maxMessageSize) {
	    byte[] handshakeMessageContentBytes = new byte[handshakeMessageContentLength];
	    System.arraycopy(handshakeMessageBytes, 12, handshakeMessageContentBytes, 0, handshakeMessageContentLength);
	    handshakeMessageSendBuffer = ArrayConverter.concatenate(
		    handshakeMessageSendBuffer,
		    prepareHandshakeMessageSend(handshakeMessageContentBytes, handshakeMessage
			    .getHandshakeMessageType().getValue(), sendHandshakeMessageSeq, maxMessageSize));
	} else {
	    handshakeMessageSendBuffer = ArrayConverter.concatenate(handshakeMessageSendBuffer, handshakeMessageBytes);
	}

	if (handshakeMessageSendRecordList == null) {
	    handshakeMessageSendRecordList = new ArrayList<>();
	    handshakeMessageSendRecordList.add(new Record());
	}

	handshakeMessage.setRecords(handshakeMessageSendRecordList);

	if (handlingLastProtocolMessageToSend(protocolMessages, protocolMessagePointer)) {
	    sendMessages(recordHandler.wrapData(handshakeMessageSendBuffer, ProtocolMessageType.HANDSHAKE,
		    handshakeMessage.getRecords()));
	    handshakeMessageSendRecordList = null;
	    handshakeMessageSendBuffer = new byte[0];
	}
    }

    private byte[] prepareHandshakeMessageSend(byte[] handshakeMessageBytes, byte handshakeType,
	    int handshakeMessageSeq, int maxMessageSize) {
	maxMessageSize -= 12;
	int messageSize = handshakeMessageBytes.length;
	if (messageSize >= maxMessageSize) {
	    int numFragments = (int) Math.ceil(messageSize / maxMessageSize);
	    LOGGER.debug("Splitting the handshake message into {} fragments", numFragments);
	    byte[] fragmentArray = new byte[0];
	    int indexPointer, fragmentLength;
	    byte[] handshakeHeader = new byte[12];
	    handshakeHeader[0] = handshakeType;
	    handshakeHeader[1] = (byte) (messageSize >>> 16);
	    handshakeHeader[2] = (byte) (messageSize >>> 8);
	    handshakeHeader[3] = (byte) messageSize;
	    handshakeHeader[4] = (byte) (handshakeMessageSeq >>> 8);
	    handshakeHeader[5] = (byte) handshakeMessageSeq;

	    for (int fragmentSizeCounter = handshakeMessageBytes.length; fragmentSizeCounter > 14; fragmentSizeCounter -= maxMessageSize) {
		indexPointer = handshakeMessageBytes.length - fragmentSizeCounter;
		if (fragmentSizeCounter < maxMessageSize) {
		    fragmentLength = fragmentSizeCounter;
		} else {
		    fragmentLength = maxMessageSize;
		}
		handshakeHeader[6] = (byte) (indexPointer >>> 16);
		handshakeHeader[7] = (byte) (indexPointer >>> 8);
		handshakeHeader[8] = (byte) indexPointer;
		handshakeHeader[9] = (byte) (fragmentLength >>> 16);
		handshakeHeader[10] = (byte) (fragmentLength >>> 8);
		handshakeHeader[11] = (byte) fragmentLength;
		fragmentArray = ArrayConverter.concatenate(fragmentArray, handshakeHeader,
			Arrays.copyOfRange(handshakeMessageBytes, indexPointer, fragmentLength));
	    }
	    return fragmentArray;
	}
	return handshakeMessageBytes;
    }

    private void sendMessages(byte[] records) throws IOException {
	recordSendBuffer = ArrayConverter.concatenate(recordSendBuffer, records);
	if (handlingLastRecordToSend(protocolMessages, protocolMessagePointer)) {
	    LOGGER.debug("Sending the following protocol messages to TLS peer: {}",
		    ArrayConverter.bytesToHexString(recordSendBuffer));
	    int pointer = 0;
	    int currentRecordSize = 0;
	    byte[] sendBuffer = new byte[0];

	    while (pointer < recordSendBuffer.length) {
		currentRecordSize = (recordSendBuffer[pointer + 11] << 8) + recordSendBuffer[pointer + 12] + 13;
		if ((sendBuffer.length + currentRecordSize) > maxPacketSize) {
		    transportHandler.sendData(sendBuffer);
		    sendBuffer = new byte[0];
		} else {
		    sendBuffer = ArrayConverter.concatenate(sendBuffer,
			    Arrays.copyOfRange(recordSendBuffer, pointer, pointer + currentRecordSize));
		}
	    }
	    if (sendBuffer.length > 0) {
		transportHandler.sendData(sendBuffer);
	    }
	    recordSendBuffer = new byte[0];
	}
    }

    private boolean receiveAndParseNextProtocolMessage(ProtocolMessage pm) throws Exception {
	boolean errorIndicator = false;

	if (wholeRecordParsedPreviously) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		if (!loadNextUseableHandshakeRecord()) {
		    if (!fatalAlertMessageFound) {
			abortCurrentFlight();
		    }
		}
	    } else if (pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
		if (!loadChangeCipherSpecRecord()) {
		    if (!fatalAlertMessageFound) {
			abortCurrentFlight();
		    }
		}
	    } else {
		loadNextNonHandshakeNonCcsRecord();
	    }
	}

	ProtocolMessageHandler pmh = currentProtocolMessageType.getProtocolMessageHandler(
		recordContentBuffer[recordContentBufferOffset], tlsContext);

	if (!pmh.isCorrectProtocolMessage(pm)) {
	    pm = wrongMessageFound(pmh);
	} else {
	    pmh.setProtocolMessage(pm);
	}

	recordContentBufferOffset = pmh.parseMessage(recordContentBuffer, recordContentBufferOffset);

	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
	}

	if (pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    errorIndicator = alertMessageFound(pmh);
	}

	if ((pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) && !unexpectedMessageFound) {
	    addRecordsToHandshakeMessage(pm);
	    expectedHandshakeMessageSeq++;
	} else {
	    pm.addRecord(currentRecord);
	}

	protocolMessagePointer++;
	wholeRecordParsedPreviously = recordContentBufferOffset >= recordContentBuffer.length;
	return errorIndicator;
    }

    private void updateFlight(ProtocolMessage pm) {
	if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE
		|| pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
	    if (lastConnectionEnd != pm.getMessageIssuer()) {
		previousFlightBeginPointer = flightStartMessageNumber;
		previousFlightConnectionEnd = lastConnectionEnd;
		flightStartMessageNumber = protocolMessagePointer;
		digestBytesBeforeNextFlightBegin = tlsContext.getDigest().getRawBytes();
		flightRetransmitCounter = 0;
	    }
	    messageFlightPointer = protocolMessagePointer;
	    lastConnectionEnd = pm.getMessageIssuer();
	}
    }

    private void abortCurrentFlight() {
	handshakeMessageRecordMap.clear();
	handshakeMessageReassembleBitmaskMap.clear();
	reassembledHandshakeMessageMap.clear();
	wholeRecordParsedPreviously = true;
	flightStartMessageNumber = previousFlightBeginPointer;
	protocolMessagePointer = flightStartMessageNumber;
	tlsContext.getDigest().setRawBytes(digestBytesBeforeNextFlightBegin);
	flightRetransmitCounter++;
    }

    private void addRecordsToHandshakeMessage(ProtocolMessage handshakeMessage) {
	List<Record> recordList = handshakeMessageRecordMap.get(expectedHandshakeMessageSeq);
	for (Record record : recordList) {
	    handshakeMessage.addRecord(record);
	}
    }

    private ProtocolMessage getNextWorkflowProtocolMessage() {
	protocolMessagePointer++;
	return getCurrentWorkflowProtocolMessage();
    }

    private ProtocolMessage getCurrentWorkflowProtocolMessage() {
	if (protocolMessagePointer < protocolMessages.size()) {
	    return protocolMessages.get(protocolMessagePointer);
	}
	return null;
    }

    private boolean alertMessageFound(ProtocolMessageHandler pmh) {
	AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
	am.setMessageIssuer(ConnectionEnd.SERVER);
	if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
	    LOGGER.debug("The workflow execution is stopped because of a FATAL error");
	    return false;
	}
	return true;
    }

    private ProtocolMessage wrongMessageFound(ProtocolMessageHandler pmh) {
	LOGGER.debug("The configured protocol message is not equal to the message being parsed or the message was not found.");
	removeNextProtocolMessages(protocolMessages, protocolMessagePointer);
	pmh.initializeProtocolMessage();
	ProtocolMessage pm = pmh.getProtocolMessage();
	protocolMessages.add(pm);
	unexpectedMessageFound = true;
	return pm;
    }

    private boolean loadNextNonHandshakeNonCcsRecord() throws Exception {
	Record rcvRecord;
	try {
	    rcvRecord = loadSingleNextRecord();
	} catch (SocketTimeoutException ste) {
	    return false;
	}
	ProtocolMessageType rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord
		.getContentType().getValue());
	long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;

	while ((rcvRecordProtocolMessageType == ProtocolMessageType.HANDSHAKE || rcvRecordProtocolMessageType == ProtocolMessageType.CHANGE_CIPHER_SPEC)
		&& (System.currentTimeMillis() <= endTimeMillies)) {
	    try {
		rcvRecord = loadSingleNextRecord();
		if (containsFatalAlertMessage(rcvRecord)) {
		    return false;
		}
	    } catch (SocketTimeoutException ste) {
		return false;
	    }
	    rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord.getContentType().getValue());
	}
	return (rcvRecordProtocolMessageType != ProtocolMessageType.HANDSHAKE && rcvRecordProtocolMessageType != ProtocolMessageType.CHANGE_CIPHER_SPEC);
    }

    private Record loadSingleNextRecord() throws Exception {
	Record rcvRecord = receiveNextValidRecord();
	ProtocolMessageType rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord
		.getContentType().getValue());
	switch (rcvRecordProtocolMessageType) {
	    case HANDSHAKE:
		processHandshakeRecord(rcvRecord);
		break;
	    case ALERT:
	    case HEARTBEAT:
	    case APPLICATION_DATA:
		updateRecordVariables(rcvRecord);
	    case CHANGE_CIPHER_SPEC:
		processChangeCipherSpecRecord(rcvRecord);
		break;
	    default:
		break;
	}
	return rcvRecord;
    }

    private boolean loadChangeCipherSpecRecord() throws Exception {
	long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;
	while ((changeCipherSpecRecord != null) && (System.currentTimeMillis() <= endTimeMillies)) {
	    try {
		if (containsFatalAlertMessage(loadSingleNextRecord())) {
		    return false;
		}
	    } catch (SocketTimeoutException ste) {
		return false;
	    }
	}
	if (changeCipherSpecRecord != null) {
	    updateRecordVariables(changeCipherSpecRecord);
	    return true;
	}
	return false;
    }

    private boolean containsFatalAlertMessage(Record record) {
	if (record.getContentType().getValue() == ProtocolMessageType.ALERT.getValue()) {
	    byte[] recordContent = record.getProtocolMessageBytes().getValue();
	    int numAlertMessagesInRecord = recordContent.length / 2;
	    if (numAlertMessagesInRecord == 1) {
		if (recordContent[0] == AlertLevel.FATAL.getValue()) {
		    fatalAlertMessageFound = true;
		    return true;
		}
	    } else {
		for (int i = 0; i < numAlertMessagesInRecord; i += 2) {
		    if (recordContent[0] == AlertLevel.FATAL.getValue()) {
			fatalAlertMessageFound = true;
			return true;
		    }
		}
	    }
	    return false;
	}
	return false;
    }

    private void processChangeCipherSpecRecord(Record ccsRecord) {
	if (changeCipherSpecRecord == null) {
	    changeCipherSpecRecord = ccsRecord;
	}
    }

    private boolean loadNextUseableHandshakeRecord() throws Exception {
	boolean correctMessageAvailable = false;
	long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;
	while (!correctMessageAvailable && (System.currentTimeMillis() <= endTimeMillies)) {
	    try {
		if (containsFatalAlertMessage(loadSingleNextRecord())) {
		    return false;
		}
	    } catch (SocketTimeoutException ste) {
		return false;
	    }
	    if (checkCompleteHandshakeMessageAvailable(expectedHandshakeMessageSeq)) {
		correctMessageAvailable = true;
		currentRecord = null;
		recordContentBuffer = reassembledHandshakeMessageMap.get(expectedHandshakeMessageSeq);
		recordContentBufferOffset = 0;
		currentProtocolMessageType = ProtocolMessageType.HANDSHAKE;
	    }
	}
	return correctMessageAvailable;
    }

    private void updateRecordVariables(Record record) {
	currentRecord = record;
	recordContentBuffer = record.getProtocolMessageBytes().getValue();
	recordContentBufferOffset = 0;
	currentProtocolMessageType = ProtocolMessageType.getContentType(record.getContentType().getValue());
    }

    private void processHandshakeRecord(Record handshakeRecord) {
	byte[] recordData = handshakeRecord.getProtocolMessageBytes().getValue();
	List<Integer> affectedHandshakeMessages = new ArrayList<>();
	int workPointer = 0;
	byte handshakeMessageType;
	int handshakeMessageSize;
	int handshakeMessageSeq;
	int handshakeMessageFragOffset;
	int handshakeMessageFragSize;

	while ((workPointer + 12) < recordData.length) {
	    handshakeMessageType = recordData[workPointer];
	    handshakeMessageSize = (recordData[workPointer + 1] << 16) + (recordData[workPointer + 2] << 8)
		    + recordData[workPointer + 3];
	    handshakeMessageSeq = (recordData[workPointer + 4] << 8) + recordData[workPointer + 5];
	    handshakeMessageFragOffset = (recordData[workPointer + 6] << 16) + (recordData[workPointer + 7] << 8)
		    + recordData[workPointer + 8];
	    handshakeMessageFragSize = (recordData[workPointer + 9] << 16) + (recordData[workPointer + 10] << 8)
		    + recordData[workPointer + 11];
	    workPointer += 12;

	    if ((handshakeMessageFragSize + workPointer) > recordData.length) {
		throw new MalformedMessageException(
			"The received handshake message (fragment) claims to contain more data than it actually does.");
	    }
	    if (handshakeMessageFragSize > handshakeMessageSize) {
		throw new MalformedMessageException(
			"The received handshake message (fragment) claims to contain a fragment that's bigger than the actual handshake message length.");
	    }
	    if ((handshakeMessageFragOffset + handshakeMessageFragSize) > handshakeMessageSize) {
		throw new MalformedMessageException(
			"The received handshake message fragment is out of the the handshake message bounds implicated by its handshake message length.");
	    }

	    if (handshakeMessageSeq >= expectedHandshakeMessageSeq) {
		if (!affectedHandshakeMessages.contains(handshakeMessageSeq)) {
		    affectedHandshakeMessages.add(handshakeMessageSeq);
		}
		processHandshakeMessageFragment(handshakeMessageType, handshakeMessageSize, handshakeMessageSeq,
			handshakeMessageFragOffset, handshakeMessageFragSize, recordData, workPointer);
	    }
	    workPointer += handshakeMessageFragSize;
	}

	for (Integer affectedHandshakeMessage : affectedHandshakeMessages) {
	    addHandshakeRecordToRecordMap(affectedHandshakeMessage, handshakeRecord);
	}
    }

    private void processHandshakeMessageFragment(byte handshakeMessageType, int handshakeMessageSize,
	    int handshakeMessageSeq, int handshakeMessageFragOffset, int handshakeMessageFragSize, byte[] recordData,
	    int workPointer) {

	if (createKeyInReassembleMaps(handshakeMessageSize, handshakeMessageSeq)) {
	    byte[] header = createCompleteHandshakeMessageHeader(handshakeMessageType, handshakeMessageSeq,
		    handshakeMessageSize);
	    handshakeMessageReassembleBitmaskMap.get(handshakeMessageSeq).set(0, 11, true);
	    System.arraycopy(header, 0, reassembledHandshakeMessageMap.get(handshakeMessageSeq), 0, 12);
	}

	handshakeMessageReassembleBitmaskMap.get(handshakeMessageSeq).set(handshakeMessageFragOffset,
		(handshakeMessageFragOffset + handshakeMessageFragSize - 1), true);
	System.arraycopy(recordData, (workPointer + handshakeMessageFragOffset),
		reassembledHandshakeMessageMap.get(handshakeMessageSeq), handshakeMessageFragOffset,
		handshakeMessageFragSize);
    }

    private boolean checkCompleteHandshakeMessageAvailable(int handshakeMessageSeq) {
	if (reassembledHandshakeMessageMap.containsKey(handshakeMessageSeq)) {
	    return checkHandshakeMessageCompleteness(handshakeMessageSeq);
	}
	return false;
    }

    private boolean checkHandshakeMessageCompleteness(int handshakeMessageSeq) {
	return handshakeMessageReassembleBitmaskMap.get(handshakeMessageSeq).cardinality() == handshakeMessageReassembleBitmaskMap
		.get(handshakeMessageSeq).length();
    }

    private byte[] createCompleteHandshakeMessageHeader(byte handshakeType, int handshakeMessageSeq,
	    int handshakeMessageSize) {
	byte[] output = new byte[12];
	output[0] = handshakeType;
	output[1] = (byte) (handshakeMessageSize >>> 16);
	output[2] = (byte) (handshakeMessageSize >>> 8);
	output[3] = (byte) handshakeMessageSize;
	output[4] = (byte) (handshakeMessageSeq >>> 8);
	output[5] = (byte) handshakeMessageSeq;
	output[9] = output[1];
	output[10] = output[2];
	output[11] = output[3];
	return output;
    }

    private boolean createKeyInReassembleMaps(int handshakeMessageSize, int handshakeMessageSeq) {
	if (!handshakeMessageReassembleBitmaskMap.containsKey(handshakeMessageSeq)) {
	    handshakeMessageReassembleBitmaskMap.put(handshakeMessageSeq, new BitSet(handshakeMessageSize));
	    reassembledHandshakeMessageMap.put(handshakeMessageSeq, new byte[handshakeMessageSize]);
	    return true;
	}
	return false;
    }

    private void addHandshakeRecordToRecordMap(int handshakeMessageSeq, Record record) {
	if (handshakeMessageRecordMap.containsKey(handshakeMessageSeq)) {
	    handshakeMessageRecordMap.get(handshakeMessageSeq).add(record);
	} else {
	    ArrayList<Record> recordList = new ArrayList<>();
	    recordList.add(record);
	    handshakeMessageRecordMap.put(handshakeMessageSeq, recordList);
	}
    }

    private Record receiveNextValidRecord() throws Exception {
	Record nextRecord = receiveNextRecord();
	while (!checkRecordValidity(nextRecord)) {
	    nextRecord = receiveNextRecord();
	}
	return nextRecord;
    }

    private Record receiveNextRecord() throws Exception {
	if (recordBuffer.isEmpty()) {
	    processNextPacket();
	}
	Record out = (Record) recordBuffer.get(0);
	recordBuffer.remove(0);
	return out;
    }

    private boolean checkRecordValidity(Record record) {
	if (record.getEpoch().getValue() != epochCounter) {
	    return false;
	}
	return true;
    }

    private void processNextPacket() throws Exception {
	recordBuffer = recordHandler.parseRecords(receiveNextPacket());
    }

    private byte[] receiveNextPacket() throws Exception {
	return transportHandler.fetchData();
    }

    /**
     * In a case the protocol message received was not equal to the messages in
     * our protocol message list, we have to clear our protocol message list.
     * 
     * @param protocolMessages
     * @param fromIndex
     */
    private void removeNextProtocolMessages(List<ProtocolMessage> protocolMessages, int fromIndex) {

	for (int i = protocolMessages.size() - 1; i >= fromIndex; i--) {
	    protocolMessages.remove(i);
	}
    }

    private byte[] prepareProtocolMessageBytes(ProtocolMessage pm) {
	// get protocol message handler
	ProtocolMessageHandler handler = pm.getProtocolMessageHandler(tlsContext);
	// create a protocol message
	byte[] pmBytes = handler.prepareMessage();
	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug(pm.toString());
	}
	// return the protocol message bytes in case we are handling a normal
	// protocol message
	// otherwise, if handling a dummy protocol message, ruturn a null byte
	// array
	if (pm.isGoingToBeSent()) {
	    return pmBytes;
	} else {
	    return new byte[0];
	}
    }

    /**
     * In case we are handling last protocol message, this protocol message has
     * to be flushed out. The reasons for flushing out the message can be
     * following: 1) it is the last protocol message 2) the next protocol
     * message should come from the different peer 3) the next protocol message
     * has a different content type
     * 
     * @param protocolMessages
     * @param pointer
     * @return
     */
    private boolean handlingLastProtocolMessageToSend(List<ProtocolMessage> protocolMessages, int pointer) {
	ProtocolMessage currentProtocolMessage = protocolMessages.get(pointer);
	return (handlingLastRecordToSend(protocolMessages, pointer) || currentProtocolMessage.getProtocolMessageType() != (protocolMessages
		.get(pointer + 1).getProtocolMessageType()));
    }

    /**
     * In case we are handling last record message, this record message has to
     * be flushed out. The reasons for flushing out the record messages can be
     * following: 1) it is the last record message 2) the next record message
     * should come from the different peer
     * 
     * @param protocolMessages
     * @param pointer
     * @return
     */
    private boolean handlingLastRecordToSend(List<ProtocolMessage> protocolMessages, int pointer) {
	return ((protocolMessages.size() == (pointer + 1)) || (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext
		.getMyConnectionEnd()));
    }

    public void setMaxPacketSize(int maxPacketSize) {
	if (this.maxPacketSize > 16397) {
	    this.maxPacketSize = 16397;
	} else {
	    this.maxPacketSize = this.maxPacketSize;
	}
    }
}
