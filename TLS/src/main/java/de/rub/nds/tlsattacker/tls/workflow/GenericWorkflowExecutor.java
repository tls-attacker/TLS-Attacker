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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class GenericWorkflowExecutor implements WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(GenericWorkflowExecutor.class);

    /**
     * indicates if the workflow was already executed
     */
    protected boolean executed = false;

    protected RecordHandler recordHandler;

    protected final TlsContext tlsContext;

    protected final TransportHandler transportHandler;

    MessageBytesCollector messageBytesCollector;

    protected WorkflowContext workflowContext;

    public GenericWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	this.tlsContext = tlsContext;
	this.transportHandler = transportHandler;
	this.recordHandler = new RecordHandler(tlsContext);
	tlsContext.setRecordHandler(recordHandler);
	this.messageBytesCollector = new MessageBytesCollector();
	this.workflowContext = new WorkflowContext();
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
	if (executed) {
	    throw new IllegalStateException("The workflow has already been" + " executed. Create a new Workflow.");
	}
	executed = true;

	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	ensureMyLastProtocolMessagesHaveRecords(protocolMessages);
	try {
	    while (workflowContext.getProtocolMessagePointer() < protocolMessages.size()
		    && workflowContext.isProceedWorkflow()) {
		ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
		    handleMyProtocolMessage(protocolMessages);
		} else {
		    handleProtocolMessagesFromPeer(protocolMessages);
		}
	    }
	} catch (WorkflowExecutionException | CryptoException | IOException e) {
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	} finally {
	    // remove all unused protocol messages
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	}
    }

    private void handleMyProtocolMessage(List<ProtocolMessage> protocolMessages) throws IOException {
	ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	prepareMyProtocolMessageBytes(pm);
	prepareMyRecordsIfNeeded(pm);
	sendDataIfMyLastMessage(protocolMessages);
	workflowContext.incrementProtocolMessagePointer();
    }

    /**
     * Uses protocol message handler to prepare raw protocol message bytes
     * 
     * @param pm
     */
    protected void prepareMyProtocolMessageBytes(ProtocolMessage pm) {
	LOGGER.debug("Preparing the following protocol message to send: {}", pm.getClass());
	ProtocolMessageHandler handler = pm.getProtocolMessageHandler(tlsContext);
	byte[] pmBytes = handler.prepareMessage();
	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug(pm.toString());
	}
	// append the prepared protocol message bytes
	if (pm.isGoingToBeSent()) {
	    messageBytesCollector.appendProtocolMessageBytes(pmBytes);
	}
    }

    /**
     * Prepares records for a given protocol message if this protocol message
     * contains a list of records
     * 
     * @param pm
     */
    protected void prepareMyRecordsIfNeeded(ProtocolMessage pm) {
	if (pm.getRecords() != null && !pm.getRecords().isEmpty()) {
	    byte[] records = recordHandler.wrapData(messageBytesCollector.getProtocolMessageBytes(),
		    pm.getProtocolMessageType(), pm.getRecords());
	    messageBytesCollector.appendRecordBytes(records);
	    messageBytesCollector.flushProtocolMessageBytes();
	}
    }

    /**
     * This function buffers all the collected records and sends them when the
     * last protocol message should be sent.
     * 
     * @param protocolMessages
     * @throws IOException
     */
    protected void sendDataIfMyLastMessage(List<ProtocolMessage> protocolMessages) throws IOException {
	if (handlingMyLastProtocolMessage(protocolMessages, workflowContext.getProtocolMessagePointer())
		&& messageBytesCollector.getRecordBytes().length != 0) {
	    LOGGER.debug("Records going to be sent: {}",
		    ArrayConverter.bytesToHexString(messageBytesCollector.getRecordBytes()));
	    transportHandler.sendData(messageBytesCollector.getRecordBytes());
	    messageBytesCollector.flushRecordBytes();
	}
    }

    /**
     * 
     * @param protocolMessages
     * @throws IOException
     */
    protected void handleProtocolMessagesFromPeer(List<ProtocolMessage> protocolMessages) throws IOException {
	List<Record> records = fetchRecords();
	List<List<Record>> recordsOfSameContentList = createListsOfRecordsOfTheSameContentType(records);

	for (List<Record> recordsOfSameContent : recordsOfSameContentList) {
	    byte[] rawProtocolMessageBytes = getRawProtocolBytesFromRecords(recordsOfSameContent);
	    ProtocolMessageType protocolMessageType = ProtocolMessageType.getContentType(recordsOfSameContent.get(0)
		    .getContentType().getValue());
	    parseRawBytesIntoProtocolMessages(rawProtocolMessageBytes, protocolMessages, protocolMessageType);
	    ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer() - 1);
	    pm.setRecords(recordsOfSameContent);
	}
    }

    /**
     * 
     * @param rawProtocolMessageBytes
     * @param protocolMessages
     * @param protocolMessageType
     */
    protected void parseRawBytesIntoProtocolMessages(byte[] rawProtocolMessageBytes,
	    List<ProtocolMessage> protocolMessages, ProtocolMessageType protocolMessageType) {
	int dataPointer = 0;
	while (dataPointer != rawProtocolMessageBytes.length && workflowContext.isProceedWorkflow()) {
	    ProtocolMessageHandler pmh = protocolMessageType.getProtocolMessageHandler(
		    rawProtocolMessageBytes[dataPointer], tlsContext);
	    identifyCorrectProtocolMessage(protocolMessages, pmh);

	    dataPointer = pmh.parseMessage(rawProtocolMessageBytes, dataPointer);
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
	    }
	    handleIncomingAlert(pmh);
	    workflowContext.incrementProtocolMessagePointer();
	}
    }

    /**
     * 
     * @param pmh
     */
    private void handleIncomingAlert(ProtocolMessageHandler pmh) {
	if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
	    am.setMessageIssuer(ConnectionEnd.SERVER);
	    if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
		LOGGER.debug("The workflow execution is stopped because of a FATAL error");
		workflowContext.setProceedWorkflow(false);
	    }
	}
    }

    /**
     * 
     * @param protocolMessages
     * @param pmh
     */
    private void identifyCorrectProtocolMessage(List<ProtocolMessage> protocolMessages, ProtocolMessageHandler pmh) {
	ProtocolMessage pm = null;
	if (workflowContext.getProtocolMessagePointer() < protocolMessages.size()) {
	    pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	}
	if (pm != null && pmh.isCorrectProtocolMessage(pm)) {
	    pmh.setProtocolMessage(pm);
	} else {
	    // the configured message is not the same as
	    // the message being parsed, we clean the
	    // next protocol messages
	    LOGGER.debug("The configured protocol message is not equal to "
		    + "the message being parsed or the message was not found.");
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	    pmh.initializeProtocolMessage();
	    pm = pmh.getProtocolMessage();
	    protocolMessages.add(pm);
	}
    }

    /**
     * 
     * @param records
     * @return
     */
    protected byte[] getRawProtocolBytesFromRecords(List<Record> records) {
	byte[] result = new byte[0];
	for (Record r : records) {
	    result = ArrayConverter.concatenate(result, r.getProtocolMessageBytes().getValue());
	}
	return result;
    }

    /**
     * Creates a list of records of the same content type
     * 
     * @param records
     * @return
     */
    protected List<List<Record>> createListsOfRecordsOfTheSameContentType(List<Record> records) {
	List<List<Record>> result = new LinkedList();
	int recordPointer = 0;
	Record record = records.get(recordPointer);
	List<Record> currentRecords = new LinkedList<>();
	currentRecords.add(record);
	result.add(currentRecords);
	recordPointer++;
	while (recordPointer < records.size()) {
	    ProtocolMessageType previousMessageType = ProtocolMessageType.getContentType(record.getContentType()
		    .getValue());
	    record = records.get(recordPointer);
	    ProtocolMessageType currentMessageType = ProtocolMessageType.getContentType(record.getContentType()
		    .getValue());
	    if (currentMessageType == previousMessageType) {
		currentRecords.add(record);
	    } else {
		currentRecords = new LinkedList<>();
		currentRecords.add(record);
		result.add(currentRecords);
	    }
	    recordPointer++;
	}
	return result;
    }

    /**
     * Fetches a list of records from the server
     * 
     * @return
     * @throws IOException
     */
    protected List<Record> fetchRecords() throws IOException {
	// todo: this can be done better and more performant, but it is ok for
	// now
	byte[] rawResponse = transportHandler.fetchData();
	List<Record> records;
	int sHandshStatus = tlsContext.getServerHandshakeStatus();
	int dataPointer = 0;
	int recordCount = 0;
	byte[] rawResponseWithoutFinished = null;
	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.SERVER && sHandshStatus != 0) {
	    switch (sHandshStatus) {
		case 1:
		    LOGGER.debug("HandshakeStatus 1");
		    rawResponse = transportHandler.fetchData();
		    while (dataPointer != rawResponse.length) {
			byte[] byteLength = { rawResponse[dataPointer + 3], rawResponse[dataPointer + 4] };
			int length = ArrayConverter.bytesToInt(byteLength);
			int lastByte = dataPointer + 5 + length;
			byte[] rawBytesFromCurrentRecord = Arrays.copyOfRange(rawResponse, dataPointer, lastByte);
			recordCount++;
			dataPointer = lastByte;
			if (recordCount == 5) {
			    tlsContext.setFinishedRecords(rawBytesFromCurrentRecord);
			} else if (recordCount == 4) {
			    rawResponseWithoutFinished = Arrays.copyOfRange(rawResponse, 0, lastByte);
			}
		    }
		    tlsContext.setServerHandshakeStatus(3);
		    break;
		case 2:
		    LOGGER.debug("HandshakeStatus 2");
		    rawResponse = transportHandler.fetchData();
		    while (dataPointer != rawResponse.length) {
			byte[] byteLength = { rawResponse[dataPointer + 3], rawResponse[dataPointer + 4] };
			int length = ArrayConverter.bytesToInt(byteLength);
			int lastByte = dataPointer + 5 + length;
			byte[] rawBytesFromCurrentRecord = Arrays.copyOfRange(rawResponse, dataPointer, lastByte);
			recordCount++;
			dataPointer = lastByte;
			if (recordCount == 3) {
			    tlsContext.setFinishedRecords(rawBytesFromCurrentRecord);
			} else if (recordCount == 2) {
			    rawResponseWithoutFinished = Arrays.copyOfRange(rawResponse, 0, lastByte);
			}
		    }
		    tlsContext.setServerHandshakeStatus(3);
		    break;
		case 3:
		    LOGGER.debug("HandshakeStatus 3");
		    rawResponseWithoutFinished = tlsContext.getFinishedRecords();
		    tlsContext.setServerHandshakeStatus(0);
		    break;
	    }
	    records = recordHandler.parseRecords(rawResponseWithoutFinished);

	} else {
	    LOGGER.debug("HandshakeStatus default");
	    while ((records = recordHandler.parseRecords(rawResponse)) == null) {
		rawResponse = ArrayConverter.concatenate(rawResponse, transportHandler.fetchData());
	    }
	    if (records.isEmpty()) {
		throw new WorkflowExecutionException("The configured protocol message was not found, "
			+ "the server does not send any data.");
	    }
	}
	return records;
    }

    /**
     * In a case the protocol message received was not equal to the messages in
     * our protocol message list, we have to clear our protocol message list.
     * 
     * @param protocolMessages
     * @param fromIndex
     */
    protected void removeNextProtocolMessages(List<ProtocolMessage> protocolMessages, int fromIndex) {
	for (int i = protocolMessages.size() - 1; i >= fromIndex; i--) {
	    protocolMessages.remove(i);
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
    protected boolean handlingMyLastProtocolMessageWithContentType(List<ProtocolMessage> protocolMessages, int pointer) {
	ProtocolMessage currentProtocolMessage = protocolMessages.get(pointer);
	return ((protocolMessages.size() == (pointer + 1))
		|| (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext.getMyConnectionEnd()) || currentProtocolMessage
		    .getProtocolMessageType() != (protocolMessages.get(pointer + 1).getProtocolMessageType()));
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
    protected boolean handlingMyLastProtocolMessage(List<ProtocolMessage> protocolMessages, int pointer) {
	return ((protocolMessages.size() == (pointer + 1)) || (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext
		.getMyConnectionEnd()));
    }

    /**
     * Every last protocol message that is going to be sent from my peer has to
     * have a record.
     * 
     * @param protocolMessages
     */
    protected void ensureMyLastProtocolMessagesHaveRecords(List<ProtocolMessage> protocolMessages) {
	for (int pmPointer = 0; pmPointer < protocolMessages.size(); pmPointer++) {
	    ProtocolMessage pm = protocolMessages.get(pmPointer);
	    if (handlingMyLastProtocolMessageWithContentType(protocolMessages, pmPointer)) {
		if (pm.getRecords() == null || pm.getRecords().isEmpty()) {
		    pm.addRecord(new Record());
		}
	    }
	}
    }
}
