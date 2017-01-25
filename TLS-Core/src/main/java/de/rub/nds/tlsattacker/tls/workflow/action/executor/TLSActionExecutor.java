/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * This ActionExecutor tries to perform Actions in a way that imitates a TLS
 * Client/Server.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSActionExecutor extends ActionExecutor {

    private final TlsContext context;
    private final WorkflowContext workflowContext;

    public TLSActionExecutor(TlsContext context, WorkflowContext workflowContext) {
        this.context = context;
        this.workflowContext = workflowContext;
    }

    /**
     * Sends a list of ProtocolMessage
     * 
     * @param messages
     *            Protocolmessages to send
     * @return List of actually send Messages
     */
    @Override
    public List<ProtocolMessage> sendMessages(List<ProtocolMessage> messages) {
        MessageBytesCollector messageBytesCollector = new MessageBytesCollector();
        for (ProtocolMessage message : messages) {
            byte[] protocolMessageBytes = prepareProtocolMessageBytes(message);
            if (message.isGoingToBeSent()) {
                messageBytesCollector.appendProtocolMessageBytes(protocolMessageBytes);
            }
            if (message.getRecords() != null && !message.getRecords().isEmpty()) {
                byte[] recordBytes = prepareRecords(message, messageBytesCollector);
                messageBytesCollector.appendRecordBytes(recordBytes);
                messageBytesCollector.flushProtocolMessageBytes();
            }
        }
        try {
            sendData(context.getTransportHandler(), messageBytesCollector);
        } catch (IOException ex) {
            // TODO
        }
        return messages;
    }

    /**
     * Receives messages, and tries to receive the messages specified in
     * messages
     * 
     * @param messages
     *            Messages which should be received
     * @return Actually received Messages
     */
    @Override
    public List<ProtocolMessage> receiveMessages(List<ProtocolMessage> messages) {
        List<ProtocolMessage> receivedList = new LinkedList<>();
        try {
            receivedList = handleProtocolMessagesFromPeer(messages);
        } catch (IOException ex) {
            // TODO
        } catch (Exception ex) {
            LOGGER.info("Uncaught exception while parsing the received Messages", ex);
        }
        return receivedList;

    }

    /**
     * Sends all messageBytes in the MessageByteCollector with the specified
     * TransportHandler
     * 
     * @param handler
     *            TransportHandler to send the Data with
     * @param messageBytesCollector
     *            MessageBytes to send
     * @throws IOException
     *             Thrown if something goes wrong while sending
     */
    private void sendData(TransportHandler handler, MessageBytesCollector messageBytesCollector) throws IOException {
        if (messageBytesCollector.getRecordBytes().length != 0) {
            LOGGER.debug("Records going to be sent: {}",
                    ArrayConverter.bytesToHexString(messageBytesCollector.getRecordBytes()));
            handler.sendData(messageBytesCollector.getRecordBytes());
            messageBytesCollector.flushRecordBytes();
        }
    }

    /**
     * Chooses the correct handler for the ProtocolMessage and returns the
     * preparedMessage bytes
     * 
     * @param message
     *            Message to prepare
     * @return Prepared message bytes for the ProtocolMessage
     */
    private byte[] prepareProtocolMessageBytes(ProtocolMessage message) {
        LOGGER.debug("Preparing the following protocol message to send: {}", message.getClass());
        ProtocolMessageHandler handler = message.getProtocolMessageHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage();
        return protocolMessageBytes;
    }

    /**
     * Prepares records for a given protocol message
     * 
     * @param message
     *            Message which contains the records
     * @param messageBytesCollector
     *            Messagebyte collector to use
     * @return Byte array containing the prepared Records
     */
    private byte[] prepareRecords(ProtocolMessage message, MessageBytesCollector messageBytesCollector) {
        byte[] records = context.getRecordHandler().wrapData(messageBytesCollector.getProtocolMessageBytes(),
                message.getProtocolMessageType(), message.getRecords());
        return records;

    }

    /**
     * Returns true if the List contains an ArbitraryMessage
     * 
     * @param protocolMessages
     *            Protocol messages to search in
     * @return True if it contains atleast one ArbitraryMessage
     */
    private boolean containsArbitaryMessage(List<ProtocolMessage> protocolMessages) {
        for (ProtocolMessage message : protocolMessages) {
            if (message instanceof ArbitraryMessage) {
                return true;
            }
        }
        return false;
    }

    /**
     * Reads records in and parses them into protocol messages
     * 
     * @param protocolMessages
     *            Protocol messages we are expecting to receive
     * @return ReceivedProtocolMessages
     * @throws IOException
     *             Thrown if something goes wrong while reading in records
     */
    private List<ProtocolMessage> handleProtocolMessagesFromPeer(List<ProtocolMessage> protocolMessages)
            throws IOException {

        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        List<Record> records = readRecords();
        while (records != null && records.size() > 0) {
            receivedMessages.addAll(parseRecords(records));
            records = null;
            records = context.getRecordHandler().parseFinishedBytes();
            if (records == null) {
                // Do we expect more data?
                if (receivedMessages.size() != protocolMessages.size() || containsArbitaryMessage(protocolMessages)) {
                    records = readRecords();
                }
            }
        }
        return receivedMessages;
    }

    /**
     * Parses a list of Records into a List of ProtocolMessage objects
     * 
     * @param records
     *            Records to be parsed
     * @return List of ProtocolMessage objects
     */
    private List<ProtocolMessage> parseRecords(List<Record> records) {
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        List<List<Record>> recordsOfSameContentList = createListsOfRecordsOfTheSameContentType(records);
        for (List<Record> recordsOfSameContent : recordsOfSameContentList) {
            byte[] rawProtocolMessageBytes = convertRecordsToProtocolMessageBytes(recordsOfSameContent);
            ProtocolMessageType protocolMessageType = ProtocolMessageType.getContentType(recordsOfSameContent.get(0)
                    .getContentType().getValue());
            receivedMessages
                    .addAll(parseRawProtocolMessageBytes(rawProtocolMessageBytes, protocolMessageType, context));
            if (!context.isRenegotiation()) {
                for (ProtocolMessage pm : receivedMessages) {
                    pm.setRecords(recordsOfSameContent);
                    // If we received more than one message in the records
                    // we set the records of all messages
                }
            } else {
                handleRenegotiation();
            }
        }
        return receivedMessages;
    }

    /**
     * Handles a renegotiation request.
     */
    private void handleRenegotiation() {
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
     * Tries to parse the raw protocol message bytes into
     * 
     * @param rawProtocolMessageBytes
     *            raw protocol message bytes to parse
     * @param protocolMessageType
     *            The type of the protocol message that should be parsed
     * @param context
     *            The TLSContext to use
     * @return List of parsed ProtocolMessage
     */
    private List<ProtocolMessage> parseRawProtocolMessageBytes(byte[] rawProtocolMessageBytes,
            ProtocolMessageType protocolMessageType, TlsContext context) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        while (dataPointer < rawProtocolMessageBytes.length) {
            ProtocolMessageHandler pmh = protocolMessageType.getProtocolMessageHandler(
                    rawProtocolMessageBytes[dataPointer], context);
            if (Arrays.equals(rawProtocolMessageBytes,
                    new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 })) {
                context.setRenegotiation(true);
            } else {
                pmh.initializeProtocolMessage();
                dataPointer = pmh.parseMessage(rawProtocolMessageBytes, dataPointer);
                LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
                receivedMessages.add(pmh.getProtocolMessage());
                if (receivedFatalAlert(pmh)) {
                    if (!context.isFuzzingMode()) {
                        workflowContext.setProceedWorkflow(false);
                    }
                }
            }
        }
        return receivedMessages;
    }

    /**
     * Returns true if the protocolMessage in the protocolMessageHandler is a
     * fatal alert
     * 
     * @param protocolMessageHandler
     *            ProtocolmessageHandler to analyze
     */
    private boolean receivedFatalAlert(ProtocolMessageHandler protocolMessageHandler) {
        if (protocolMessageHandler.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
            AlertMessage am = (AlertMessage) protocolMessageHandler.getProtocolMessage();
            if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
                LOGGER.debug("The workflow received a FATAL error");
                return true;
            }
        }
        return false;
    }

    /**
     * Converts a List of Records into a byte array containing their
     * protocolmessage bytes
     * 
     * @param records
     *            Records to convert
     * @return A byte array containing the raw protocol message bytes
     */
    private byte[] convertRecordsToProtocolMessageBytes(List<Record> records) {
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
    private List<List<Record>> createListsOfRecordsOfTheSameContentType(List<Record> records) {
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
     * Fetches a Data from the TransportHandler and parses it into Records
     * 
     * @return A List of parsed Records
     * @throws IOException
     *             Thrown if something goes wrong while fetching the Data from
     *             the Transporthandler
     */
    private List<Record> readRecords() throws IOException {
        List<Record> records = null;
        byte[] rawResponse = context.getTransportHandler().fetchData();
        while ((records = context.getRecordHandler().parseRecords(rawResponse)) == null) {
            rawResponse = ArrayConverter.concatenate(rawResponse, context.getTransportHandler().fetchData());
        }
        return records;
    }

}
