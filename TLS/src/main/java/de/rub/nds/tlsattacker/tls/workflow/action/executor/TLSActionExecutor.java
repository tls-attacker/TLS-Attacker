/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.FatalAertMessageException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSActionExecutor extends ActionExecutor {

    private TlsContext context;
    private WorkflowContext workflowContext;

    public TLSActionExecutor(TlsContext context, WorkflowContext workflowContext) {
	this.context = context;
	this.workflowContext = workflowContext;
    }

    private int pointer = 0;

    @Override
    public List<ProtocolMessage> sendMessages(TlsContext tlsContext, List<ProtocolMessage> messages) throws IOException {
	MessageBytesCollector messageBytesCollector = new MessageBytesCollector();
	for (ProtocolMessage message : messages) {
	    prepareMyProtocolMessageBytes(message, tlsContext, messageBytesCollector);
	    prepareMyRecordsIfNeeded(message, tlsContext, messageBytesCollector);
	}
	sendData(tlsContext, messageBytesCollector);
	return messages;
    }

    @Override
    public List<ProtocolMessage> receiveMessages(TlsContext tlsContext, List<ProtocolMessage> messages)
	    throws IOException {
	pointer = 0;
	List<ProtocolMessage> receivedList = handleProtocolMessagesFromPeer(messages, tlsContext);
	return receivedList;

    }

    /**
     * This function buffers all the collected records and sends them when the
     * last protocol message should be sent.
     * 
     * @param protocolMessages
     * @throws IOException
     */
    protected void sendData(TlsContext context, MessageBytesCollector messageBytesCollector) throws IOException {
	if (messageBytesCollector.getRecordBytes().length != 0) {
	    LOG.log(Level.FINER, "Records going to be sent: {}",
		    ArrayConverter.bytesToHexString(messageBytesCollector.getRecordBytes()));
	    context.getTransportHandler().sendData(messageBytesCollector.getRecordBytes());
	    messageBytesCollector.flushRecordBytes();
	}
    }

    /**
     * Uses protocol message handler to prepare raw protocol message bytes
     * 
     * @param message
     * @param context
     */
    protected void prepareMyProtocolMessageBytes(ProtocolMessage message, TlsContext context,
	    MessageBytesCollector messageBytesCollector) {
	LOG.log(Level.FINER, "Preparing the following protocol message to send: {}", message.getClass());
	ProtocolMessageHandler handler = message.getProtocolMessageHandler(context);
	byte[] pmBytes = handler.prepareMessage();
	// LOG.log(Level.FINEST, message.toString());

	// append the prepared protocol message bytes
	if (message.isGoingToBeSent()) {
	    messageBytesCollector.appendProtocolMessageBytes(pmBytes);
	}
    }

    /**
     * Prepares records for a given protocol message if this protocol message
     * contains a list of records
     * 
     * @param message
     * @param context
     */
    protected void prepareMyRecordsIfNeeded(ProtocolMessage message, TlsContext context,
	    MessageBytesCollector messageBytesCollector) {
	if (message.getRecords() != null && !message.getRecords().isEmpty()) {
	    byte[] records = context.getRecordHandler().wrapData(messageBytesCollector.getProtocolMessageBytes(),
		    message.getProtocolMessageType(), message.getRecords());
	    messageBytesCollector.appendRecordBytes(records);
	    messageBytesCollector.flushProtocolMessageBytes();
	}
    }

    private boolean containsArbitaryMessage(List<ProtocolMessage> protocolMessages) {
	for (ProtocolMessage message : protocolMessages) {
	    if (message instanceof ArbitraryMessage) {
		return true;
	    }
	}
	return false;
    }

    /**
     * 
     * @param protocolMessages
     * @param context
     * @throws IOException
     */
    protected List<ProtocolMessage> handleProtocolMessagesFromPeer(List<ProtocolMessage> protocolMessages,
	    TlsContext context) throws IOException {

	List<ProtocolMessage> receivedMessages = new LinkedList<>();
	List<Record> records = fetchRecords(context);
	while (records != null && records.size() > 0) {
	    List<List<Record>> recordsOfSameContentList = createListsOfRecordsOfTheSameContentType(records);
	    for (List<Record> recordsOfSameContent : recordsOfSameContentList) {
		byte[] rawProtocolMessageBytes = getRawProtocolBytesFromRecords(recordsOfSameContent);
		ProtocolMessageType protocolMessageType = ProtocolMessageType.getContentType(recordsOfSameContent
			.get(0).getContentType().getValue());
		receivedMessages.addAll(parseRawBytesIntoProtocolMessages(rawProtocolMessageBytes, protocolMessages,
			protocolMessageType, context));
		if (!context.isRenegotiation()) {
		    for (ProtocolMessage pm : receivedMessages) {
			pm.setRecords(recordsOfSameContent);
			// If we received more than one message in the records
			// we set the records of all messages
		    }
		} else {
		    handleRenegotiation(context);
		}
	    }

	    records = parseFinishedBytes(context);
	    if (records == null) {
		// Do we expect more data?
		if (receivedMessages.size() != protocolMessages.size() || containsArbitaryMessage(protocolMessages)) {
		    records = fetchRecords(context);
		}
	    }
	}
	return receivedMessages;
    }

    /**
     * Handles a renegotiation request.
     */
    protected void handleRenegotiation(TlsContext context) {
	// workflowContext.setProtocolMessagePointer(0);
	context.getDigest().reset();

	/*
	 * if there is no keystore file we can not authenticate per certificate
	 * and if isClientauthentication is true, we do not need to change the
	 * WorkflowTrace
	 */
	if (context.getKeyStore() != null && !context.isClientAuthentication()) {
	    context.setClientAuthentication(true);
	    // RenegotiationWorkflowConfiguration reneWorkflowConfig = new
	    // RenegotiationWorkflowConfiguration(context);
	    // reneWorkflowConfig.createWorkflow();
	} else if (context.getKeyStore() == null && context.isSessionResumption()) {
	    // RenegotiationWorkflowConfiguration reneWorkflowConfig = new
	    // RenegotiationWorkflowConfiguration(context);
	    // reneWorkflowConfig.createWorkflow();
	}

	context.setSessionResumption(false);
	context.setRenegotiation(false);
	// TODO We have to deal with renegotiation differently
	// executeWorkflow();
    }

    /**
     * 
     * @param rawProtocolMessageBytes
     * @param protocolMessages
     * @param protocolMessageType
     */
    protected List<ProtocolMessage> parseRawBytesIntoProtocolMessages(byte[] rawProtocolMessageBytes,
	    List<ProtocolMessage> protocolMessages, ProtocolMessageType protocolMessageType, TlsContext context) {
	int dataPointer = 0;
	List<ProtocolMessage> receivedMessages = new LinkedList<>();
	while (dataPointer < rawProtocolMessageBytes.length) {
	    ProtocolMessageHandler pmh = null;
            pmh = protocolMessageType.getProtocolMessageHandler(rawProtocolMessageBytes[dataPointer], context);
            if (Arrays.equals(rawProtocolMessageBytes,
		    new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 })) {
		context.setRenegotiation(true);
	    } else {
		identifyCorrectProtocolMessage(protocolMessages, pmh, context);

		dataPointer = pmh.parseMessage(rawProtocolMessageBytes, dataPointer);
		LOG.log(Level.FINE, "The following message was parsed: {}", pmh.getProtocolMessage().toString());
		receivedMessages.add(pmh.getProtocolMessage());
		if (receivedFatalAlert(pmh, context)) {
		    if (!context.isFuzzingMode()) {
			workflowContext.setProceedWorkflow(false);
		    }
		}
		pointer++;
	    }
	}
	return receivedMessages;
    }

    /**
     * 
     * @param pmh
     */
    private boolean receivedFatalAlert(ProtocolMessageHandler pmh, TlsContext context) {
	if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
	    if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
		LOG.log(Level.FINE, "The workflow execution is stopped because of a FATAL error");
		return true;
	    }
	}
	return false;
    }

    /**
     * 
     * @param protocolMessages
     * @param protocolMessageHandler
     */
    private List<ProtocolMessage> identifyCorrectProtocolMessage(List<ProtocolMessage> protocolMessages,
	    ProtocolMessageHandler protocolMessageHandler, TlsContext context) {
	List<ProtocolMessage> identifiedMessages = new LinkedList<>();

	ProtocolMessage protocolMessage = null;
	if (pointer < protocolMessages.size()) {
	    protocolMessage = protocolMessages.get(pointer);
	}
	if (protocolMessage != null && protocolMessage.getClass() == ArbitraryMessage.class) {
	    protocolMessageHandler.initializeProtocolMessage();
	    protocolMessage = protocolMessageHandler.getProtocolMessage();
	    identifiedMessages.add(protocolMessage);
	} else if (protocolMessage != null && protocolMessageHandler.isCorrectProtocolMessage(protocolMessage)) {
	    protocolMessageHandler.setProtocolMessage(protocolMessage);
	} else {
            if(protocolMessage != null && protocolMessage.isRequired())
            {
                LOG.log(Level.FINE, "The configured protocol message is not equal to "
			+ "the message being parsed or the message was not found.");
		if(!context.isFuzzingMode()){
                    workflowContext.setProceedWorkflow(false);
                }
            }
	    protocolMessageHandler.initializeProtocolMessage();
            protocolMessage = protocolMessageHandler.getProtocolMessage();
            identifiedMessages.add(protocolMessage);
            
		//pointer++;
		//identifiedMessages.addAll(identifyCorrectProtocolMessage(protocolMessages, protocolMessageHandler,
		//	context));
	}
	return identifiedMessages;
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
	if (records == null || records.isEmpty()) {
	    return result;
	}
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
    protected List<Record> fetchRecords(TlsContext context) throws IOException {
	List<Record> records = null;
	if (records == null) {
	    byte[] rawResponse = context.getTransportHandler().fetchData();
	    while ((records = context.getRecordHandler().parseRecords(rawResponse)) == null) {
		rawResponse = ArrayConverter.concatenate(rawResponse, context.getTransportHandler().fetchData());
	    }
	}
	return records;
    }

    protected List<Record> parseFinishedBytes(TlsContext context) throws IOException {
	List<Record> records = null;
	// parse stored Finished bytes into a record
	if (context.getRecordHandler().getFinishedBytes() != null) {
	    records = context.getRecordHandler().parseRecords(context.getRecordHandler().getFinishedBytes());
	    context.getRecordHandler().setFinishedBytes(null);
	}
	return records;
    }

    private static final Logger LOG = Logger.getLogger(TLSActionExecutor.class.getName());
}
