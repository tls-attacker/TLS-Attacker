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

    private int protocolMessagePointer, recordBufferOffset, messageFlightPointer, receivedHandshakeMessageCounter;

    private Record currentRecord;

    private List<de.rub.nds.tlsattacker.tls.record.messages.Record> recordBuffer = new LinkedList<>();

    private byte[] recordContentBuffer = new byte[0];

    private ProtocolMessageType currentProtocolMessageType = ProtocolMessageType.ALERT;

    private ConnectionEnd lastConnectionEnd;
    
    private int maxBogusRecordNumber = 20;
    
    private int maxWaitForValidHandshakeRecordTime = 3000;

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

	lastConnectionEnd = tlsContext.getMyConnectionEnd();
	protocolMessages = workflowTrace.getProtocolMessages();
	protocolMessagePointer = 0;
	try {
	    ProtocolMessage pm;
	    boolean proceedWorkflow = true;

	    while (protocolMessagePointer < protocolMessages.size() && proceedWorkflow) {
		pm = getCurrentWorkflowProtocolMessage();
		updateFlightCounter(pm);
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
                    sendNextProtocolMessage(pm);
		} else {
                    parseNextRecievedProtocolMessage();
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
        byte[] collectedRecords = new byte[0];
        byte[] mbBytes = new byte[0];
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
    }

    private void updateFlightCounter(ProtocolMessage pm) {
	if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE
		|| pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
	    if (lastConnectionEnd != pm.getMessageIssuer()) {
		messageFlightPointer = protocolMessagePointer;
	    }
	} else {
	    messageFlightPointer = protocolMessagePointer;
	}
	lastConnectionEnd = pm.getMessageIssuer();
    }

    private boolean parseNextRecievedProtocolMessage() throws Exception {
	boolean errorIndicator = false;
	if (recordBufferOffset >= recordContentBuffer.length) {
	    fillRecordContentBuffer();
	}
        ProtocolMessage pm = getNextWorkflowProtocolMessage();
        if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
            prepareHandshakeMessageParse();
        }
	ProtocolMessageHandler pmh = getCurrentProtocolMessageHandler();
	recordBufferOffset = pmh.parseMessage(recordContentBuffer, recordBufferOffset);
	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
	}
	if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    errorIndicator = alertMessageFound(pmh);
	}
	if (recordBufferOffset >= recordContentBuffer.length) {
	    pm.addRecord(currentRecord);
	}
	return errorIndicator;
    }

    private void prepareHandshakeMessageParse() throws Exception {
        boolean correctRecord = false;
        int bogusRecordCounter = 0;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForValidHandshakeRecordTime;
        
        while (!correctRecord && (bogusRecordCounter <= maxBogusRecordNumber) && (System.currentTimeMillis() <= endTimeMillies)) {
            if (currentProtocolMessageType == ProtocolMessageType.HANDSHAKE) {
                int receivedHandshakeMessageSeq = recordContentBuffer[recordBufferOffset + 3] << 8 + recordContentBuffer[recordBufferOffset + 4];
                if (receivedHandshakeMessageSeq == receivedHandshakeMessageCounter) {
                    correctRecord = true;
                }
                else if (receivedHandshakeMessageSeq > receivedHandshakeMessageCounter) {
                    
                }
                
            }
            else
            {
                fillRecordContentBuffer();
                bogusRecordCounter++;
            }
        }
        if (!correctRecord) {
            throw new IllegalArgumentException("No adequate protocol records were received.");
        }
//        HandshakeMessage hm = (HandshakeMessage) pm;
//        HandshakeMessageDtlsFields hmf = (HandshakeMessageDtlsFields) hm.getMessageFields();
//        if (hmf.getMessageSeq().getValue() == receivedHandshakeMessageCounter) {
//            if (checkHandshakeMessageFragmented(hmf)) {
//                //Defragment
//            }
//        }
//        else {
//            
//        }
//
//        return pm;
    }
    
    
    
    private boolean checkHandshakeMessageFragmented(HandshakeMessageDtlsFields hmdf) {
        return !hmdf.getLength().getValue().equals(hmdf.getFragmentLength().getValue());
    }

    //private ProtocolMessage getNextWorkflowProtocolMessage(ProtocolMessageHandler pmh) {
     private ProtocolMessage getNextWorkflowProtocolMessage() {
	ProtocolMessage pm;
	if (protocolMessagePointer >= protocolMessages.size()) {
           //pm = wrongMessageFound(pmh);
           return null;
        }
	pm = protocolMessages.get(protocolMessagePointer);
        
	//if (!pmh.isCorrectProtocolMessage(pm)) {
	//    pm = wrongMessageFound(pmh);
	//} else {
	//    pmh.setProtocolMessage(pm);
	//}
	protocolMessagePointer++;
	return pm;
    }

    private ProtocolMessage getCurrentWorkflowProtocolMessage() {
	if (protocolMessagePointer < protocolMessages.size()) {
	    return protocolMessages.get(protocolMessagePointer);
	}
	return null;
    }

    private ProtocolMessageHandler getCurrentProtocolMessageHandler() {
	return currentProtocolMessageType
		.getProtocolMessageHandler(recordContentBuffer[recordBufferOffset], tlsContext);
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

    private void fillRecordContentBuffer() throws Exception {
	currentRecord = getNextValidRecord();
	recordContentBuffer = currentRecord.getProtocolMessageBytes().getValue();
	currentProtocolMessageType = ProtocolMessageType.getContentType(currentRecord.getContentType().getValue());
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