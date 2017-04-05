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
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An ActionExecutor for SSL, this is nessecary since the default ActionExecutor
 * is unable to guess which Handler should be used when receiving Messages since
 * SSL2 does not have a record layer.
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSLActionExecutor extends ActionExecutor {

    private static final Logger LOGGER = LogManager.getLogger(SSLActionExecutor.class);

    private boolean proceed = true;

    private final TlsContext context;

    public SSLActionExecutor(TlsContext context) {
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
    public MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records) {
        if (!proceed) {
            return new MessageActionResult(new LinkedList<AbstractRecord>(), new LinkedList<ProtocolMessage>());
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
                    context.getRecordLayer().updateEncryptionCipher();
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
        ProtocolMessageHandler handler = message.getHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        return protocolMessageBytes;
    }

    private int flushBytesToRecords(MessageBytesCollector collector, ProtocolMessageType type,
            List<AbstractRecord> records, int recordPosition) {
        int length = collector.getProtocolMessageBytesStream().length;
        List<AbstractRecord> toFillList = getEnoughRecords(length, recordPosition, records);
        collector.appendRecordBytes(context.getRecordLayer().prepareRecords(collector.getProtocolMessageBytesStream(),
                type, toFillList));
        collector.flushProtocolMessageBytes();
        return recordPosition + toFillList.size();
    }

    private List<AbstractRecord> getEnoughRecords(int length, int position, List<AbstractRecord> records) {
        List<AbstractRecord> toFillList = new LinkedList<>();
        int recordLength = 0;
        while (recordLength < length) {
            if (position >= records.size()) {
                if (context.getConfig().isCreateRecordsDynamically()) {
                    records.add(context.getRecordLayer().getFreshRecord());
                } else {
                    return toFillList;
                }
            }
            AbstractRecord record = records.get(position);
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
        List<AbstractRecord> records = new LinkedList<>();
        List<ProtocolMessage> messages = new LinkedList<>();
        try {
            if (!proceed) {
                return new MessageActionResult(new LinkedList<AbstractRecord>(), new LinkedList<ProtocolMessage>());
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

    private List<AbstractRecord> parseRecords(byte[] recordBytes) {
        List<AbstractRecord> receivedRecords = context.getRecordLayer().parseRecords(recordBytes);
        return receivedRecords;
    }

    private List<ProtocolMessage> parseMessages(List<AbstractRecord> records) {
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        int recordPosition = 0;
        do {
            List<AbstractRecord> recordSubGroup = getNextRecordSubgroupd(records, recordPosition);
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

                ProtocolMessageHandler pmh = new SSL2ServerHelloHandler(context);
                result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);

            } catch (ParserException | AdjustmentException E) {
                ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, ProtocolMessageType.UNKNOWN, null);
                result = pmh.parseMessage(cleanProtocolMessageBytes, dataPointer);
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

    private byte[] getCleanBytes(List<AbstractRecord> recordSubGroup) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : recordSubGroup) {
            try {
                stream.write(record.getCleanProtocolMessageBytes().getValue());
            } catch (IOException ex) {
                LOGGER.warn("Could not write CleanProtocolMessage bytes to Array", ex);
            }
        }
        return stream.toByteArray();
    }

    private List<AbstractRecord> getNextRecordSubgroupd(List<AbstractRecord> records, int recordPosition) {
        List<AbstractRecord> returnList = new LinkedList<>();
        if (records.size() <= recordPosition) {
            return returnList;
        }
        ProtocolMessageType type = records.get(recordPosition).getContentMessageType();
        for (int i = recordPosition; i < records.size(); i++) {
            AbstractRecord record = records.get(i);
            if (record.getContentMessageType() == type) {
                returnList.add(record);
            } else {
                return returnList;
            }
        }
        return returnList;

    }

    private ProtocolMessageType getProtocolMessageType(List<AbstractRecord> recordSubGroup) {
        ProtocolMessageType type = null;
        for (AbstractRecord record : recordSubGroup) {
            if (type == null) {
                type = record.getContentMessageType();
            } else {
                ProtocolMessageType tempType = ProtocolMessageType.getContentType(record.getContentMessageType()
                        .getValue());
                if (tempType != type) {
                    LOGGER.warn("Mixed Subgroup detected");
                }
            }

        }
        return type;
    }

    private void decryptRecords(List<AbstractRecord> records) {
        for (AbstractRecord record : records) {
            context.getRecordLayer().decryptRecord(record);
            if (record.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                context.getRecordLayer().updateDecryptionCipher();// TODO
                                                                  // unfortunate
            }
        }
    }

}
