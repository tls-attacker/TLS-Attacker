/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.handler.ParserResult;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ActionHelper {

    protected static final Logger LOGGER = LogManager.getLogger(ActionHelper.class.getName());

    private ActionHelper() {
    }

    /**
     * Receives messages, and tries to receive the messages specified in
     * messages
     *
     * @param expectedMessages
     *            Messages which should be received
     * @return Actually received Messages
     */
    public static MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages, TlsContext context) {
        context.setTalkingConnectionEndType(context.getConfig().getMyConnectionPeer());

        List<AbstractRecord> records = new LinkedList<>();
        List<ProtocolMessage> messages = new LinkedList<>();
        try {
            byte[] recievedBytes = null;
            boolean shouldContinue = true;
            do {
                recievedBytes = receiveByteArray(context);
                if (recievedBytes.length != 0) {
                    records = parseRecords(recievedBytes, context);
                    List<List<AbstractRecord>> recordGroups = getRecordGroups(records);
                    for (List<AbstractRecord> recordGroup : recordGroups) {
                        adjustContext(recordGroup, context);
                        decryptRecords(recordGroup, context);
                        messages.addAll(parseMessages(recordGroup, context));
                        if (context.getConfig().isQuickReceive()) {
                            boolean receivedFatalAlert = false;
                            for (ProtocolMessage message : messages) {
                                if (message instanceof AlertMessage) {
                                    AlertMessage alert = (AlertMessage) message;
                                    if (alert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                                        receivedFatalAlert = true;
                                    }
                                }
                            }
                            boolean receivedAllConfiguredMessages = true;
                            if (messages.size() != expectedMessages.size() && !context.getConfig().isEarlyStop()) {
                                receivedAllConfiguredMessages = false;
                            } else {
                                for (int i = 0; i < expectedMessages.size(); i++) {
                                    if (i >= messages.size()) {
                                        receivedAllConfiguredMessages = false;
                                    }
                                    if (!expectedMessages.get(i).getClass().equals(messages.get(i).getClass())) {
                                        receivedAllConfiguredMessages = false;
                                    }
                                }
                            }
                            if (receivedAllConfiguredMessages || receivedFatalAlert) {
                                LOGGER.debug("Quickreceive active. Stopping listening");
                                shouldContinue = false;
                                break;
                            }
                        }
                    }
                }
            } while (recievedBytes.length != 0 && shouldContinue);

        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while recieving for Messages.");
            LOGGER.debug(ex);
        }
        return new MessageActionResult(records, messages);
    }

    private static byte[] receiveByteArray(TlsContext context) throws IOException {
        return context.getTransportHandler().fetchData();
    }

    private static List<AbstractRecord> parseRecords(byte[] recordBytes, TlsContext context) {
        List<AbstractRecord> receivedRecords = context.getRecordLayer().parseRecords(recordBytes);
        return receivedRecords;
    }

    private static List<ProtocolMessage> parseMessages(List<AbstractRecord> records, TlsContext context) {
        if (records.isEmpty()) {
            return new LinkedList<>();
        }
        byte[] cleanProtocolMessageBytes = getCleanBytes(records);
        return recieveMessage(cleanProtocolMessageBytes, getProtocolMessageType(records), context);
    }

    private static List<ProtocolMessage> recieveMessage(byte[] cleanProtocolMessageBytes,
            ProtocolMessageType typeFromRecord, TlsContext context) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        while (dataPointer < cleanProtocolMessageBytes.length) {
            ParserResult result = null;
            try {
                HandshakeMessageType handshakeMessageType = HandshakeMessageType
                        .getMessageType(cleanProtocolMessageBytes[dataPointer]);
                ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, handshakeMessageType);
                result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);
            } catch (ParserException | AdjustmentException E) {
                LOGGER.warn("Could not parse Message as a CorrectMessage, parsing as UnknownHandshakeMessage instead!");
                LOGGER.debug(E);
                // Parsing as the specified Message did not work, try parsing it
                // as an Unknown message
                try {
                    if (typeFromRecord == ProtocolMessageType.HANDSHAKE) {
                        HandshakeMessageType handshakeType = HandshakeMessageType.UNKNOWN;
                        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, handshakeType);
                        result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);
                    }
                } catch (ParserException ex) {
                    LOGGER.warn("Could not parse Message as UnknownHandshakeMessage, parsing as UnknownMessage instead!");
                    LOGGER.debug(ex);
                } finally {
                    if (result == null) {
                        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, ProtocolMessageType.UNKNOWN,
                                null);
                        result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);
                    }
                }
            }
            dataPointer = result.getParserPosition();
            LOGGER.debug("The following message was parsed: {}", result.getMessage().toString());
            receivedMessages.add(result.getMessage());
        }
        return receivedMessages;
    }

    private static byte[] getCleanBytes(List<AbstractRecord> recordSubGroup) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : recordSubGroup) {
            try {
                stream.write(record.getCleanProtocolMessageBytes().getValue());
            } catch (IOException ex) {
                LOGGER.warn("Could not write CleanProtocolMessage bytes to Array");
                LOGGER.debug(ex);
            }
        }
        return stream.toByteArray();
    }

    private static List<List<AbstractRecord>> getRecordGroups(List<AbstractRecord> records) {
        List<List<AbstractRecord>> returnList = new LinkedList<>();
        if (records.isEmpty()) {
            return returnList;
        }
        List<AbstractRecord> subGroup = new LinkedList<>();
        ProtocolMessageType currentSearchType = records.get(0).getContentMessageType();
        for (AbstractRecord record : records) {
            if (record.getContentMessageType() == currentSearchType) {
                subGroup.add(record);
            } else {
                returnList.add(subGroup);
                subGroup = new LinkedList<>();
                currentSearchType = record.getContentMessageType();
                subGroup.add(record);
            }
        }
        returnList.add(subGroup);
        return returnList;

    }

    private static ProtocolMessageType getProtocolMessageType(List<AbstractRecord> recordSubGroup) {
        ProtocolMessageType type = null;
        for (AbstractRecord record : recordSubGroup) {
            if (type == null) {
                type = record.getContentMessageType();
            } else {
                ProtocolMessageType tempType = ProtocolMessageType.getContentType(record.getContentMessageType()
                        .getValue());
                if (tempType != type) {
                    LOGGER.error("Mixed Subgroup detected");
                }
            }

        }
        return type;
    }

    private static void decryptRecords(List<AbstractRecord> records, TlsContext context) {
        for (AbstractRecord record : records) {
            context.getRecordLayer().decryptRecord(record);
        }
    }

    private static void adjustContext(List<AbstractRecord> recordGroup, TlsContext context) {
        for (AbstractRecord record : recordGroup) {
            record.adjustContext(context);
        }
    }

    public static MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records,
            TlsContext context) {
        context.setTalkingConnectionEndType(context.getConfig().getConnectionEndType());

        if ((context.getConfig().isStopRecievingAfterFatal() && context.isReceivedFatalAlert())) {
            return new MessageActionResult(new LinkedList<AbstractRecord>(), new LinkedList<ProtocolMessage>());
        }
        if (records == null) {
            LOGGER.trace("No Records Specified, creating emtpy list");
            records = new LinkedList<>();
        }
        int recordPosition = 0;
        ProtocolMessageType lastType = null;
        MessageBytesCollector messageBytesCollector = new MessageBytesCollector();
        for (ProtocolMessage message : messages) {
            if (message.getProtocolMessageType() != lastType && lastType != null
                    && context.getConfig().isFlushOnMessageTypeChange()) {
                recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
                if (lastType == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                    // TODO this should not be here
                    context.getRecordLayer().updateEncryptionCipher();
                }
            }
            lastType = message.getProtocolMessageType();
            LOGGER.debug("Preparing " + message.toCompactString());
            byte[] protocolMessageBytes = prepareProtocolMessageBytes(message, context);
            if (message.isGoingToBeSent()) {
                messageBytesCollector.appendProtocolMessageBytes(protocolMessageBytes);
            }
            if (context.getConfig().isCreateIndividualRecords()) {
                recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
            }
            if (context.getSelectedProtocolVersion().isTLS13() && context.isUpdateKeys() == true) {
                LOGGER.debug("Setting new Cipher in RecordLayer");
                RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context);
                context.getRecordLayer().setRecordCipher(recordCipher);
                context.getRecordLayer().updateDecryptionCipher();
                context.getRecordLayer().updateEncryptionCipher();
            }
        }
        flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
        try {
            sendData(messageBytesCollector, context);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return new MessageActionResult(records, messages);
    }

    private static int flushBytesToRecords(MessageBytesCollector collector, ProtocolMessageType type,
            List<AbstractRecord> records, int recordPosition, TlsContext context) {
        int length = collector.getProtocolMessageBytesStream().length;
        List<AbstractRecord> toFillList = getEnoughRecords(length, recordPosition, records, context);
        collector.appendRecordBytes(context.getRecordLayer().prepareRecords(collector.getProtocolMessageBytesStream(),
                type, toFillList));
        collector.flushProtocolMessageBytes();
        return recordPosition + toFillList.size();
    }

    private static List<AbstractRecord> getEnoughRecords(int length, int position, List<AbstractRecord> records,
            TlsContext context) {
        List<AbstractRecord> toFillList = new LinkedList<>();
        int recordLength = 0;
        while (recordLength < length) {
            if (position >= records.size()) {
                if (context.getConfig().isCreateRecordsDynamically()) {
                    LOGGER.trace("Creating new Record");
                    records.add(context.getRecordLayer().getFreshRecord());
                } else {
                    return toFillList;
                }
            }
            AbstractRecord record = records.get(position);
            toFillList.add(record);
            if (record.getMaxRecordLengthConfig() == null) {
                record.setMaxRecordLengthConfig(context.getConfig().getDefaultMaxRecordData());
            }
            recordLength += record.getMaxRecordLengthConfig();
            position++;
        }
        return toFillList;
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
    private static void sendData(MessageBytesCollector collector, TlsContext context) throws IOException {
        context.getTransportHandler().sendData(collector.getRecordBytes());
        collector.flushRecordBytes();
    }

    private static byte[] prepareProtocolMessageBytes(ProtocolMessage message, TlsContext context) {
        LOGGER.debug("Preparing the following protocol message to send: {}", message.toCompactString());
        ProtocolMessageHandler handler = message.getHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        return protocolMessageBytes;
    }
}
