/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.dtls.record.HandshakeFragmentHandler;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecord;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ParserResult;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DTLSActionExecutor extends ActionExecutor {

    private static final Logger LOGGER = LogManager.getLogger(DTLSActionExecutor.class);

    private byte[] handshakeMessageSendBuffer;
    private byte[] recordSendBuffer;
    // TODO put this in config
    private int messageParseBufferOffset;
    private int maxWaitForExpectedRecord = 3000;
    private int maxRetransmits = 0;
    private int serverEpochCounter;
    private int maxPacketSize = 1400;
    private int maxHandshakeReorderBufferSize = 100;
    private int retransmitCounter;
    private int retransmitEpoch;

    private DtlsRecord currentRecord, changeCipherSpecRecordBuffer, parseRecordBuffer;

    private final List<byte[]> retransmitList;

    private List<Record> recordBuffer;
    private List<Record> handshakeMessageSendRecordList = null;

    private final HandshakeFragmentHandler handshakeFragmentHandler;

    private final RecordHandler recordHandler;
    private final TransportHandler transportHandler;
    private final TlsContext tlsContext;
    private List<ProtocolMessage> lastActualSendList;
    private ProtocolMessage previousMessage;

    public DTLSActionExecutor(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        recordHandler = tlsContext.getRecordHandler();
        transportHandler = tlsContext.getTransportHandler();
        handshakeFragmentHandler = new HandshakeFragmentHandler();
        recordBuffer = new LinkedList<>();
        retransmitList = new ArrayList<>();
        recordSendBuffer = new byte[0];
        handshakeMessageSendBuffer = new byte[0];
    }

    @Override
    public List<ProtocolMessage> sendMessages(List<ProtocolMessage> messages) {
        lastActualSendList = new LinkedList<>();
        try {
            if (retransmitCounter > maxRetransmits) {
                throw new WorkflowExecutionException("Retransmit Counter reached Max Retransmits!");
            }

            for (ProtocolMessage message : messages) {
                updateFlight(message, previousMessage);
                handleMyProtocolMessage(message);
                previousMessage = message;
                lastActualSendList.add(message);
            }
            sendBufferedData();
        } catch (IOException E) {
            E.printStackTrace();
            // TODO
        }
        previousMessage = null;
        handshakeMessageSendRecordList = null;
        handshakeMessageSendBuffer = new byte[0];

        return lastActualSendList;
    }

    @Override
    public List<ProtocolMessage> receiveMessages(List<ProtocolMessage> messages) {
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        ProtocolMessage receivedMessage = null;
        do {
            receivedMessage = receiveAndParseNextProtocolMessage();
            if (receivedMessage == null) {
                if (receivedMessages.isEmpty()) {
                    if (retransmitCounter < maxRetransmits) {
                        try {
                            retransmit();
                        } catch (IOException ex) {
                            throw new WorkflowExecutionException("Could not retransmit Message", ex);
                        }
                    }
                    // TODO do we have to do more?
                }
            } else {
                receivedMessages.add(receivedMessage);
            }
        } while (continueReceiving(receivedMessage != null, messages, receivedMessages));
        return receivedMessages;
    }

    private boolean continueReceiving(boolean receivedMessage, List<ProtocolMessage> expectedMessages,
            List<ProtocolMessage> received) {
        if (!receivedMessage) {
            return false;
        }
        if (tlsContext.getConfig().isWaitOnlyForExpectedDTLS()) {
            return !receivedExpected(expectedMessages, received);
        } else {
            return true;
        }
    }

    private boolean receivedExpected(List<ProtocolMessage> expectedMessages, List<ProtocolMessage> received) {
        int min = 0;
        for (ProtocolMessage message : expectedMessages) {
            if (message.isRequired()) {
                boolean found = false;
                for (int i = min; i < received.size(); i++) {
                    if (received.get(i).getClass().equals(message.getClass())) {
                        found = true;
                        min = i;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
        }
        return true;

    }

    private void handleMyProtocolMessage(ProtocolMessage pm) throws IOException {
        LOGGER.debug("Preparing the following protocol message to send: {}", pm.getClass());
        if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
            handleMyHandshakeMessage((HandshakeMessage) pm);
        } else if (pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
            handleMyChangeCipherSpecMessage(pm);
        } else {
            handleMyNonHandshakeMessage(pm);
        }

    }

    /**
     * We simply send the protocol Message, and add Records if the protocol
     * message has no records
     *
     * @param protocolMessage
     * @throws IOException
     */
    private void handleMyNonHandshakeMessage(ProtocolMessage protocolMessage) throws IOException {
        ProtocolMessageHandler pmh = null;// TODO//protocolMessage.getProtocolMessageHandler(tlsContext);

        byte[] messageBytes = pmh.prepareMessage(protocolMessage);
        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }
        byte[] record = recordHandler.wrapData(messageBytes, protocolMessage.getProtocolMessageType(),
                protocolMessage.getRecords());
        LOGGER.debug("Sending the following protocol message to DTLS peer: " + protocolMessage.getClass()
                + "\nRaw Bytes: {}", ArrayConverter.bytesToHexString(record));
        transportHandler.sendData(record);
    }

    /**
     *
     * @param protocolMessage
     * @throws IOException
     */
    private void handleMyChangeCipherSpecMessage(ProtocolMessage protocolMessage) throws IOException {
        ProtocolMessageHandler pmh = null; // TODO//protocolMessage.getProtocolMessageHandler(tlsContext);
        byte[] messageBytes = pmh.prepareMessage(protocolMessage);

        retransmitList.add(messageBytes);

        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }

        byte[] record = recordHandler.wrapData(messageBytes, ProtocolMessageType.CHANGE_CIPHER_SPEC,
                protocolMessage.getRecords());
        bufferSendData(record);
    }

    private void handleMyHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
        HandshakeMessageHandler pmh = (HandshakeMessageHandler) handshakeMessage.getHandler(tlsContext);
        byte[] handshakeMessageBytes = pmh.prepareMessage(handshakeMessage);

        handshakeMessageSendBuffer = ArrayConverter.concatenate(handshakeMessageSendBuffer,
                handshakeFragmentHandler.fragmentHandshakeMessage(handshakeMessageBytes, maxPacketSize - 25));

        retransmitList.add(handshakeMessageSendBuffer);

        if (handshakeMessageSendRecordList == null) {
            handshakeMessageSendRecordList = new ArrayList<>();
            handshakeMessageSendRecordList.add(new DtlsRecord());
        }

        handshakeMessage.setRecords(handshakeMessageSendRecordList);

        bufferSendData(recordHandler.wrapData(handshakeMessageSendBuffer, ProtocolMessageType.HANDSHAKE,
                handshakeMessage.getRecords()));

        tlsContext.setSequenceNumber(tlsContext.getSequenceNumber() + 1);
    }

    private void bufferSendData(byte[] records) {
        recordSendBuffer = ArrayConverter.concatenate(recordSendBuffer, records);
    }

    private void sendBufferedData() throws IOException {

        LOGGER.debug("Sending the following protocol messages to DTLS peer: {}",
                ArrayConverter.bytesToHexString(recordSendBuffer));
        int pointer = 0;
        int currentRecordSize = 0;
        byte[] sendBuffer = new byte[0];

        while (pointer < recordSendBuffer.length) {
            currentRecordSize = (recordSendBuffer[pointer + 11] << 8) + (recordSendBuffer[pointer + 12] & 0xFF) + 13;
            if ((sendBuffer.length + currentRecordSize) > maxPacketSize) {
                transportHandler.sendData(sendBuffer);
                sendBuffer = new byte[0];
            } else {
                sendBuffer = ArrayConverter.concatenate(sendBuffer,
                        Arrays.copyOfRange(recordSendBuffer, pointer, pointer + currentRecordSize));
                recordSendBuffer = Arrays.copyOfRange(recordSendBuffer, pointer + currentRecordSize,
                        recordSendBuffer.length);
            }
        }
        if (sendBuffer.length > 0) {
            transportHandler.sendData(sendBuffer);
        }
        recordSendBuffer = new byte[0];

    }

    private DtlsRecord getNextProtocolMessageRecord() {
        byte[] rawMessageBytes;
        DtlsRecord rcvRecord = new DtlsRecord();
        ProtocolMessageType rcvRecordContentType;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;
        while (System.currentTimeMillis() <= endTimeMillies) {
            rawMessageBytes = handshakeFragmentHandler.getHandshakeMessage();
            if (rawMessageBytes != null) {
                rcvRecord.setProtocolMessageBytes(rawMessageBytes);
                rcvRecord.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
                return rcvRecord;
            }
            try {
                rcvRecord = receiveNextValidRecord();
            } catch (IOException e) {
                rcvRecord = new DtlsRecord();
                continue;
            }
            rcvRecordContentType = ProtocolMessageType.getContentType(rcvRecord.getContentType().getValue());
            switch (rcvRecordContentType) {
                case ALERT:
                    return rcvRecord;
                case HANDSHAKE:
                    handshakeFragmentHandler.processHandshakeRecord(rcvRecord);
                    break;
                case CHANGE_CIPHER_SPEC:
                    processChangeCipherSpecRecord(rcvRecord);
                    break;
                default:
                    break;
            }
            if (changeCipherSpecReceived()) {
                return getReceivedChangeCipherSepc();
            }
        }
        return null;
    }

    private ProtocolMessage receiveAndParseNextProtocolMessage() {
        DtlsRecord rcvRecord = parseRecordBuffer;

        if (rcvRecord == null) {
            rcvRecord = getNextProtocolMessageRecord();
            if (rcvRecord == null) {
                return null;
            }
        }

        byte[] rawMessageBytes = rcvRecord.getProtocolMessageBytes().getValue();
        ProtocolMessageType rcvRecordContentType = ProtocolMessageType.getContentType(rcvRecord.getContentType()
                .getValue());
        ProtocolMessageHandler pmh = HandlerFactory.getHandler(tlsContext, rcvRecordContentType,
                HandshakeMessageType.getMessageType(rawMessageBytes[messageParseBufferOffset]));
        ParserResult result = pmh.parseMessage(rawMessageBytes, messageParseBufferOffset);
        ProtocolMessage protocolMessage = result.getMessage();
        messageParseBufferOffset = result.getParserPosition();

        LOGGER.debug("The following message was parsed: {}", protocolMessage.toString());

        switch (protocolMessage.getProtocolMessageType()) {
            case ALERT:
                if (isIncomingAlertFatal(protocolMessage) && !tlsContext.getConfig().isFuzzingMode()) {
                    throw new WorkflowExecutionException("Received a fatal Alert, aborting!");
                }
                break;
            case HANDSHAKE:
                handshakeFragmentHandler.addRecordsToHandshakeMessage(protocolMessage);
                handshakeFragmentHandler.incrementExpectedHandshakeMessageSeq();
                break;
            case CHANGE_CIPHER_SPEC:
                serverEpochCounter++;
                protocolMessage.addRecord(currentRecord);
                break;
            default:
                protocolMessage.addRecord(currentRecord);
        }

        if (messageParseBufferOffset >= rawMessageBytes.length) {
            parseRecordBuffer = null;
            messageParseBufferOffset = 0;
        } else {
            parseRecordBuffer = rcvRecord;
        }
        return protocolMessage;
    }

    public void retransmit() throws IOException {
        retransmitCounter++;
        List<ProtocolMessage> newRetransmitList = new LinkedList<>();
        LinkedList<Record> recordList = new LinkedList<>();
        for (byte[] retransmitByte : retransmitList) {
            // TODO Very hacky, needs to be verified and tested
            RetransmitMessage message = new RetransmitMessage(retransmitByte);
            lastActualSendList.add(message);
            newRetransmitList.add(message);
            recordList.add(new DtlsRecord());
            byte[] retransmittedMessage = retransmitByte;

            if (retransmittedMessage.length == 1) {
                transportHandler.sendData(recordHandler.wrapData(retransmittedMessage,
                        ProtocolMessageType.CHANGE_CIPHER_SPEC, recordList));
            } else if (retransmittedMessage.length > 2) {
                transportHandler.sendData(recordHandler.wrapData(retransmittedMessage, ProtocolMessageType.HANDSHAKE,
                        recordList));
            } else {
                LOGGER.error("Empty retransmit message bytes");
            }
            recordList.removeFirst();
        }
        sendMessages(newRetransmitList);

    }

    private boolean isIncomingAlertFatal(ProtocolMessage message) {
        AlertMessage am = (AlertMessage) message;
        return AlertLevel.getAlertLevel(am.getLevel().getValue()) != AlertLevel.FATAL;
    }

    protected DtlsRecord getHandshakeMessage() {
        DtlsRecord rcvRecord;
        DtlsRecord outRecord = new DtlsRecord();
        ProtocolMessageType rcvRecordProtocolMessageType;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;
        byte[] rawMessageBytes;

        while (System.currentTimeMillis() <= endTimeMillies) {
            rawMessageBytes = handshakeFragmentHandler.getHandshakeMessage();
            if (rawMessageBytes != null) {
                outRecord.setProtocolMessageBytes(rawMessageBytes);
                outRecord.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
                return outRecord;
            }
            try {
                rcvRecord = receiveNextValidRecord();
            } catch (IOException e) {
                continue;
            }
            rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord.getContentType().getValue());
            switch (rcvRecordProtocolMessageType) {
                case ALERT:
                    return rcvRecord;
                case HANDSHAKE:
                    handshakeFragmentHandler.processHandshakeRecord(rcvRecord);
                    break;
                case CHANGE_CIPHER_SPEC:
                    processChangeCipherSpecRecord(rcvRecord);
                    break;
                default:
                    break;
            }
        }
        // abortFlight();
        return null;
    }

    private boolean changeCipherSpecReceived() {
        return changeCipherSpecRecordBuffer != null;
    }

    private DtlsRecord getReceivedChangeCipherSepc() {
        DtlsRecord output = changeCipherSpecRecordBuffer;
        changeCipherSpecRecordBuffer = null;
        return output;
    }

    private void processChangeCipherSpecRecord(DtlsRecord ccsRecord) {
        if (changeCipherSpecRecordBuffer == null) {
            changeCipherSpecRecordBuffer = ccsRecord;
        }
    }

    /**
     * Tries to receive a new Valid record
     *
     * @return
     * @throws IOException
     */
    private DtlsRecord receiveNextValidRecord() throws IOException {
        DtlsRecord nextRecord = receiveNextRecord();
        while (!checkRecordValidity(nextRecord)) {
            nextRecord = receiveNextRecord();
        }
        return nextRecord;
    }

    private DtlsRecord receiveNextRecord() throws IOException {
        if (recordBuffer.isEmpty()) {
            processNextPacket();
        }
        DtlsRecord out = (DtlsRecord) recordBuffer.get(0);
        recordBuffer.remove(0);
        return out;
    }

    private void processNextPacket() throws IOException {
        recordBuffer = recordHandler.parseRecords(receiveNextPacket());
    }

    private boolean checkRecordValidity(DtlsRecord record) {
        return record.getEpoch().getValue() == serverEpochCounter;
    }

    private byte[] receiveNextPacket() throws IOException {
        return transportHandler.fetchData();
    }

    public void setMaxPacketSize(int maxPacketSize) {
        this.maxPacketSize = maxPacketSize;
    }

    private boolean isHandshakeOrCCS(ProtocolMessageType pmt) {
        return pmt == ProtocolMessageType.HANDSHAKE || pmt == ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    private void updateFlight(ProtocolMessage protocolMessage, ProtocolMessage previousMessage) {
        if (previousMessage != null) {
            if (isHandshakeOrCCS(protocolMessage.getProtocolMessageType())) {
                if (!isHandshakeOrCCS(previousMessage.getProtocolMessageType())) {
                    flightTransition();
                }
            }
        } else {
            flightTransition();
        }
    }

    private void flightTransition() {
        retransmitCounter = 0;
        retransmitList.clear();
    }

    public HandshakeFragmentHandler getHandshakeFragmentHandler() {
        return handshakeFragmentHandler;
    }

}
