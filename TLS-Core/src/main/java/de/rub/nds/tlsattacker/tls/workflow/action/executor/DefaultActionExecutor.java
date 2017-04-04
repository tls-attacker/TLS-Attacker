/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.handler.ParserResult;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.parser.RecordParser;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This ActionExecutor tries to perform Actions in a way that imitates a TLS
 * Client/Server.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DefaultActionExecutor extends ActionExecutor {

    private static final Logger LOGGER = LogManager.getLogger(DefaultActionExecutor.class);

    private final TlsContext context;

    private boolean proceed;

    public DefaultActionExecutor(TlsContext context) {
        this.proceed = true;
        this.context = context;
    }

    /**
     * Sends a list of ProtocolMessage
     *
     * @param messages
     *            Protocolmessages to send
     * @param records
     * @return
     *
     */
    @Override
    public MessageActionResult sendMessages(List<ProtocolMessage> messages, List<Record> records) {
        if (!proceed) {
            return new MessageActionResult(new LinkedList<Record>(), new LinkedList<ProtocolMessage>());
        }
        if (records == null) {
            records = new LinkedList<>();
        }
        int recordPosition = 0;
        ProtocolMessageType lastType = null;
        MessageBytesCollector messageBytesCollector = new MessageBytesCollector();
        for (ProtocolMessage message : messages) {
            if (message.getProtocolMessageType() != lastType && lastType != null
                    && context.getConfig().isFlushOnMessageTypeChange()) {
                recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition);
                if (lastType == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                    context.getRecordHandler().updateEncryptionCipher();
                }
            }
            lastType = message.getProtocolMessageType();
            LOGGER.debug("Preparing " + message.toCompactString());
            byte[] protocolMessageBytes = prepareProtocolMessageBytes(message);
            if (message.isGoingToBeSent()) {
                messageBytesCollector.appendProtocolMessageBytes(protocolMessageBytes);
            }
            if (context.getConfig().isCreateIndividualRecords()) {
                recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition);
            }
        }
        flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition);
        // Save Bytes and parse them afterwards
        byte[] toSendBytes = messageBytesCollector.getRecordBytes();
        try {
            sendData(messageBytesCollector);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        // TODO Parse our messages
        return new MessageActionResult(records, messages);
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
        ProtocolMessageType protocolType = message.getProtocolMessageType();

        HandshakeMessageType type = null;
        if (protocolType == ProtocolMessageType.HANDSHAKE) {
            type = ((HandshakeMessage) message).getHandshakeMessageType();
        }
        ProtocolMessageHandler handler = message.getHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        return protocolMessageBytes;
    }

    private int flushBytesToRecords(MessageBytesCollector collector, ProtocolMessageType type, List<Record> records,
            int recordPosition) {
        int length = collector.getProtocolMessageBytesStream().length;
        int recordLength = 0;
        List<Record> toFillList = getEnoughRecords(length, recordPosition, records);
        collector.appendRecordBytes(context.getRecordHandler().prepareRecords(
                collector.getProtocolMessageBytesStream(), type, toFillList));
        collector.flushProtocolMessageBytes();
        return recordPosition + toFillList.size();
    }

    private List<Record> getEnoughRecords(int length, int position, List<Record> records) {
        List<Record> toFillList = new LinkedList<>();
        int recordLength = 0;
        while (recordLength < length) {
            if (position >= records.size()) {
                if (context.getConfig().isCreateRecordsDynamically()) {
                    records.add(new Record(context.getConfig()));
                } else {
                    return toFillList;
                }
            }
            Record record = records.get(position);
            toFillList.add(record);
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
    private void sendData(MessageBytesCollector collector) throws IOException {
        context.getTransportHandler().sendData(collector.getRecordBytes());
        collector.flushRecordBytes();
    }

    /**
     * Receives messages, and tries to receive the messages specified in
     * messages
     *
     * @param expectedMessages
     *            Messages which should be received
     * @return Actually received Messages
     */
    @Override
    public MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages) {
        List<Record> records = new LinkedList<>();
        List<ProtocolMessage> messages = new LinkedList<>();
        try {
            if (!proceed) {
                return new MessageActionResult(new LinkedList<Record>(), new LinkedList<ProtocolMessage>());
            }
            byte[] recievedBytes = null;
            do {
                recievedBytes = receiveByteArray();
                if (recievedBytes.length != 0) {
                    records = parseRecords(recievedBytes);
                    decryptRecords(records);
                    messages.addAll(parseMessages(records));
                }
            } while (recievedBytes.length != 0);

        } catch (IOException ex) {
            LOGGER.warn("Received Exception while receiving Messages.", ex);
        }
        return new MessageActionResult(records, messages);
    }

    private byte[] receiveByteArray() throws IOException {
        return context.getTransportHandler().fetchData();
    }

    private List<Record> parseRecords(byte[] recordBytes) {
        List<Record> receivedRecords = context.getRecordHandler().parseRecords(recordBytes);
        return receivedRecords;
    }

    private List<ProtocolMessage> parseMessages(List<Record> records) {
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        int recordPosition = 0;
        do {
            List<Record> recordSubGroup = getNextRecordSubgroupd(records, recordPosition);
            ProtocolMessageType type = getProtocolMessageType(recordSubGroup);
            recordPosition += recordSubGroup.size();
            byte[] cleanProtocolMessageBytes = getCleanBytes(recordSubGroup);
            receivedMessages.addAll(recieveMessage(cleanProtocolMessageBytes, type));
        } while (records.size() > recordPosition);
        return receivedMessages;
    }

    private List<ProtocolMessage> recieveMessage(byte[] cleanProtocolMessageBytes, ProtocolMessageType typeFromRecord) {

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
                LOGGER.log(Level.WARN,
                        "Could not parse Message as a CorrectMessage, parsing as UnknownHandshakeMessage instead!", E);
                // Parsing as the specified Message did not work, try parsing it
                // as an Unknown message
                try {
                    if (typeFromRecord == ProtocolMessageType.HANDSHAKE) {
                        HandshakeMessageType handshakeType = HandshakeMessageType.UNKNOWN;
                        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, handshakeType);
                        result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);
                    }
                } catch (ParserException ex) {
                    LOGGER.log(Level.WARN,
                            "Could not parse Message as UnknownHandshakeMessage, parsing as UnknownMessage instead!",
                            ex);
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
        if (context.isReceivedFatalAlert()) {
            proceed = false;
        }
        return receivedMessages;
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

    private byte[] getCleanBytes(List<Record> recordSubGroup) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (Record record : recordSubGroup) {
            try {
                stream.write(record.getCleanProtocolMessageBytes().getValue());
            } catch (IOException ex) {
                LOGGER.warn("Could not write CleanProtocolMessage bytes to Array", ex);
            }
        }
        return stream.toByteArray();
    }

    private List<Record> getNextRecordSubgroupd(List<Record> records, int recordPosition) {
        List<Record> returnList = new LinkedList<>();
        if (records.size() <= recordPosition) {
            return returnList;
        }
        byte type = records.get(recordPosition).getContentType().getValue();
        for (int i = recordPosition; i < records.size(); i++) {
            Record record = records.get(i);
            if (record.getContentType().getValue() == type) {
                returnList.add(record);
            } else {
                return returnList;
            }
        }
        return returnList;

    }

    /**
     *
     * @param recordSubGroup
     * @return
     */
    private ProtocolMessageType getProtocolMessageType(List<Record> recordSubGroup) {
        ProtocolMessageType type = null;
        for (Record record : recordSubGroup) {
            if (type == null) {
                type = ProtocolMessageType.getContentType(record.getContentType().getValue());
            } else {
                ProtocolMessageType tempType = ProtocolMessageType.getContentType(record.getContentType().getValue());
                if (tempType != type) {
                    LOGGER.warn("Mixed Subgroup detected");
                }
            }

        }
        return type;
    }

    private void decryptRecords(List<Record> records) {
        for (Record record : records) {
            context.getRecordHandler().decryptRecord(record);
            if (record.getContentType().getValue() == ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue()) {
                context.getRecordHandler().updateDecryptionCipher();// TODO
                                                                    // unfortunate
            }
        }
    }
}
