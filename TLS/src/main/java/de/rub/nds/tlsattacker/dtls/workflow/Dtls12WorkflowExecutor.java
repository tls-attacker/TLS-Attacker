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

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.dtls.record.handlers.RecordHandler;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.dtls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    private int sendRetries = 4;

    private List<ProtocolMessage> protocolMessages;

    private int protocolMessagePointer = 0;

    private List<de.rub.nds.tlsattacker.tls.record.messages.Record> recordBuffer = new LinkedList<>();

    private byte[] recordContentBuffer = new byte[0];

    private int recordBufferOffset = 0;

    private ProtocolMessageType currentProtocolMessageType = ProtocolMessageType.ALERT;

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

	protocolMessages = workflowTrace.getProtocolMessages();
	protocolMessagePointer = -1;
	try {
	    byte[] rawResponse;
	    byte[] collectedRecords = null;
	    boolean proceedWorkflow = true;
	    int messageFlightPointer = 0;
	    ConnectionEnd lastConnectionEnd = tlsContext.getMyConnectionEnd();

	    byte[] mbBytes = null;
	    while (protocolMessagePointer < (protocolMessages.size() - 1) && proceedWorkflow) {
		protocolMessagePointer++;
		ProtocolMessage pm = protocolMessages.get(protocolMessagePointer);
		if (lastConnectionEnd != pm.getMessageIssuer()) {
		    messageFlightPointer = protocolMessagePointer;
		}
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
		    // it is our turn to send a message
		    LOGGER.debug("Preparing the following protocol message to send: {}", pm.getClass());
		    // create a protocol message bytes
		    byte[] pmBytes = prepareProtocolMessageBytes(pm);
		    // concatenate the protocol bytes with collected protocol
		    // bytes
		    mbBytes = ArrayConverter.concatenate(mbBytes, pmBytes);
		    // ensure the protocol message has a record if needed
		    ensureLastProtocolMessageHasRecord(protocolMessages, protocolMessagePointer);
		    // collect records and flush the collected data if needed
		    if (pm.getRecords() != null && !pm.getRecords().isEmpty()) {
			byte[] record = recordHandler.wrapData(mbBytes, pm.getProtocolMessageType(), pm.getRecords());
			mbBytes = null;
			collectedRecords = ArrayConverter.concatenate(collectedRecords, record);
			if (handlingLastProtocolMessageToSend(protocolMessages, protocolMessagePointer)
				&& collectedRecords.length != 0) {
			    // flush all the collected data
			    LOGGER.debug("Sending collected records to the TLS peer: {}",
				    ArrayConverter.bytesToHexString(collectedRecords));
			    // transportHandler.sendData(collectedRecords);
			    sendData(collectedRecords, protocolMessages, protocolMessagePointer);
			    collectedRecords = null;
			}
		    }
		} else {
		    // it is turn of our peer to send a message
		    rawResponse = transportHandler.fetchData();
		    List<de.rub.nds.tlsattacker.tls.record.messages.Record> records = recordHandler
			    .parseRecords(rawResponse);
		    // check the record list is not emptyontent type in the
		    // record
		    if (records.isEmpty()) {
			LOGGER.debug("The configured protocol message was not found, "
				+ "the server does not send any data.");
			LOGGER.debug("Retransmit # of the last message flight.");
			this.removeNextProtocolMessages(protocolMessages, protocolMessagePointer);
			unexpectedMessageFound = true;
		    } else {
			protocolMessagePointer--;
			for (de.rub.nds.tlsattacker.tls.record.messages.Record record : records) {
			    ProtocolMessageType protocolMessageType = ProtocolMessageType.getContentType(record
				    .getContentType().getValue());
			    int dataPointer = 0;
			    byte[] rawProtocolMessageBytes = record.getProtocolMessageBytes().getValue();
			    while (dataPointer != rawProtocolMessageBytes.length && proceedWorkflow) {
				ProtocolMessageHandler pmh = protocolMessageType.getProtocolMessageHandler(
					rawProtocolMessageBytes[dataPointer], tlsContext);
				pm = null;
				protocolMessagePointer++;
				if (protocolMessagePointer < protocolMessages.size()) {
				    pm = protocolMessages.get(protocolMessagePointer);
				}

				if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
				    AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
				    am.setMessageIssuer(ConnectionEnd.SERVER);
				    if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
					LOGGER.debug("The workflow execution is stopped because of a FATAL error");
					proceedWorkflow = false;
				    }
				}
			    }
			    pm.addRecord(record);
			}
		    }
		}
	    }
	} catch (WorkflowExecutionException | CryptoException | IOException e) {
	    e.printStackTrace();
	    protocolMessagePointer--;
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	} finally {
	    // remove all unused protocol messages
	    this.removeNextProtocolMessages(protocolMessages, protocolMessagePointer + 1);
	}
    }

    private void parseNextProtocolMessage() throws Exception {
	if (recordContentBuffer.length == 0) {
	    refillRecordBuffer();
	}
	ProtocolMessageHandler pmh = currentProtocolMessageType.getProtocolMessageHandler(
		recordContentBuffer[recordBufferOffset], tlsContext);
	ProtocolMessage pm = protocolMessages.get(protocolMessagePointer);
	if (!pmh.isCorrectProtocolMessage(pm)) {
	    pm = wrongMessageFound(pmh);
	} else {
	    pmh.setProtocolMessage(pm);
	}
	recordBufferOffset = pmh.parseMessage(recordContentBuffer, recordBufferOffset);
	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
	}
    }

    private ProtocolMessage wrongMessageFound(ProtocolMessageHandler pmh) {
	// the configured message is not the same as
	// the message being parsed, we clean the
	// next protocol messages
	LOGGER.debug("The configured protocol message is not equal to the message being parsed or the message was not found.");
	this.removeNextProtocolMessages(protocolMessages, protocolMessagePointer);
	pmh.initializeProtocolMessage();
	ProtocolMessage pm = pmh.getProtocolMessage();
	protocolMessages.add(pm);
	unexpectedMessageFound = true;
	return pm;
    }

    private void refillRecordBuffer() throws Exception {
	Record nextRecord = getNextValidRecord();
	recordContentBuffer = nextRecord.getProtocolMessageBytes().getValue();
	currentProtocolMessageType = ProtocolMessageType.getContentType(nextRecord.getContentType().getValue());
	recordBufferOffset = 0;
    }

    private Record getNextValidRecord() throws Exception {
	Record nextRecord = getNextRecord();
	while (!checkRecordValidity(nextRecord)) {
	    nextRecord = getNextRecord();
	}
	return nextRecord;
    }

    private Record getNextRecord() throws Exception {
	if (recordBuffer.isEmpty()) {
	    processNextPacket();
	}
	Record out = (Record) recordBuffer.get(0);
	recordBuffer.remove(0);
	return out;
    }

    private boolean checkRecordValidity(Record record) {
	// ToDo: Validity checks (replay, MAC, etc.)
	return true;
    }

    private void processNextPacket() throws Exception {
	recordBuffer = recordHandler.parseRecords(receiveNextPacket());
    }

    private byte[] receiveNextPacket() throws Exception {
	return transportHandler.fetchData();
    }

    /**
     * This function buffers all the collected records and sends them when the
     * last protocol message should be sent.
     * 
     * TODO make this configurable
     * 
     * @param collectedRecords
     * @param protocolMessages
     * @param pointer
     * @throws IOException
     */
    private void sendData(byte[] collectedRecords, List<ProtocolMessage> protocolMessages, int pointer)
	    throws IOException {
	dataToSend = ArrayConverter.concatenate(dataToSend, collectedRecords);
	if (handlingLastRecordToSend(protocolMessages, pointer)) {
	    transportHandler.sendData(dataToSend);
	    dataToSend = new byte[0];
	}
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
    private boolean handlingLastRecordToSend(List<ProtocolMessage> protocolMessages, int pointer) {
	return ((protocolMessages.size() == (pointer + 1)) || (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext
		.getMyConnectionEnd()));
    }

    /**
     * In case we are handling the last protocol message, it has to have a
     * record.
     * 
     * @param protocolMessages
     * @param protocolMessagePointer
     */
    private void ensureLastProtocolMessageHasRecord(List<ProtocolMessage> protocolMessages, int protocolMessagePointer) {
	ProtocolMessage pm = protocolMessages.get(protocolMessagePointer);
	if (handlingLastProtocolMessageToSend(protocolMessages, protocolMessagePointer)) {
	    if (pm.getRecords() == null || pm.getRecords().isEmpty()) {
		pm.addRecord(new Record());
	    }
	}
    }

}
