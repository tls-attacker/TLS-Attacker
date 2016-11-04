/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.HandshakeFragmentHandler;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecord;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DTLSActionExecutor extends ActionExecutor {

    private byte[] handshakeMessageSendBuffer, recordSendBuffer;

    private int messageParseBufferOffset, sendHandshakeMessageSeq, maxWaitForExpectedRecord = 3000, maxRetransmits = 4,
            serverEpochCounter, maxPacketSize = 1400, maxHandshakeReorderBufferSize = 100, retransmitCounter,
            retransmitEpoch;

    private DtlsRecord currentRecord, changeCipherSpecRecordBuffer, parseRecordBuffer;

    private final List<byte[]> retransmitList;

    private List<de.rub.nds.tlsattacker.tls.record.Record> recordBuffer;
    private List<de.rub.nds.tlsattacker.tls.record.Record> handshakeMessageSendRecordList = null;

    private final HandshakeFragmentHandler handshakeFragmentHandler;

    private final DtlsRecordHandler recordHandler;
    private final TransportHandler transportHandler;
    private final TlsContext tlsContext;
    private int counter = 0;
    private ProtocolMessage previousMessage = null;

    public DTLSActionExecutor(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        recordHandler = (DtlsRecordHandler) tlsContext.getRecordHandler();
        transportHandler = tlsContext.getTransportHandler();
        handshakeFragmentHandler = new HandshakeFragmentHandler();
        recordBuffer = new LinkedList<>();
        retransmitList = new ArrayList<>();
        recordSendBuffer = new byte[0];
        handshakeMessageSendBuffer = new byte[0];
    }

    @Override
    public List<ProtocolMessage> sendMessages(List<ProtocolMessage> messages){
        try {
            if (retransmitCounter < maxRetransmits) {
                throw new WorkflowExecutionException("Retransmit Counter reached Max Retransmits!");
            }

            for (ProtocolMessage message : messages) {
                updateFlight(message, previousMessage);
                handleMyProtocolMessage(message);
                previousMessage = message;
            }
            sendBufferedData();
        } catch (IOException E) {
            //TODO
        }
        previousMessage = null;
        handshakeMessageSendRecordList = null;
        handshakeMessageSendBuffer = new byte[0];
        return messages;
    }

    @Override
    public List<ProtocolMessage> receiveMessages(List<ProtocolMessage> messages){
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        for (ProtocolMessage message : messages) {
            ProtocolMessage receivedMessage = receiveAndParseNextProtocolMessage(message);
            if (receivedMessage == null) {
                // receivedMessage = handleRetransmit();//TODO
            }
            receivedMessages.add(receivedMessage);
        }
        return receivedMessages;
    }

    private void handleMyProtocolMessage(ProtocolMessage pm) throws IOException {
        LOG.log(Level.FINE, "Preparing the following protocol message to send: {}", pm.getClass());

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
        ProtocolMessageHandler pmh = protocolMessage.getProtocolMessageHandler(tlsContext);

        byte[] messageBytes = pmh.prepareMessage();
        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }
        byte[] record = recordHandler.wrapData(messageBytes, protocolMessage.getProtocolMessageType(),
                protocolMessage.getRecords());
        LOG.log(Level.FINE, "Sending the following protocol message to DTLS peer: " + protocolMessage.getClass()
                + "\nRaw Bytes: {}", ArrayConverter.bytesToHexString(record));
        transportHandler.sendData(record);
    }

    /**
     *
     * @param protocolMessage
     * @throws IOException
     */
    private void handleMyChangeCipherSpecMessage(ProtocolMessage protocolMessage) throws IOException {
        ProtocolMessageHandler pmh = protocolMessage.getProtocolMessageHandler(tlsContext);
        byte[] messageBytes = pmh.prepareMessage();

        retransmitList.add(messageBytes);

        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }

        byte[] record = recordHandler.wrapData(messageBytes, ProtocolMessageType.CHANGE_CIPHER_SPEC,
                protocolMessage.getRecords());
        bufferSendData(record);
    }

    private void handleMyHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
        ProtocolMessageHandler pmh = handshakeMessage.getProtocolMessageHandler(tlsContext);
        handshakeMessage.setMessageSeq(sendHandshakeMessageSeq);
        byte[] handshakeMessageBytes = pmh.prepareMessage();

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

        sendHandshakeMessageSeq++;
    }

    private void bufferSendData(byte[] records) {
        recordSendBuffer = ArrayConverter.concatenate(recordSendBuffer, records);
    }

    private void sendBufferedData() throws IOException {

        LOG.log(Level.FINE, "Sending the following protocol messages to DTLS peer: {}",
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

    private DtlsRecord getNextProtocolMessageRecord(ProtocolMessage pm) {
        switch (pm.getProtocolMessageType()) {
            case HANDSHAKE:
                return getHandshakeMessage();
            case CHANGE_CIPHER_SPEC:
                return getChangeCipherSpecMessage();
            default:
                return getNonHandshakeNonCcsMessages();
        }
    }

    private ProtocolMessage receiveAndParseNextProtocolMessage(ProtocolMessage protocolMessage) {
        DtlsRecord rcvRecord = parseRecordBuffer;

        if (rcvRecord == null) {
            rcvRecord = getNextProtocolMessageRecord(protocolMessage);
            if (rcvRecord == null) {
                return null;
            }
        }

        byte[] rawMessageBytes = rcvRecord.getProtocolMessageBytes().getValue();
        ProtocolMessageType rcvRecordContentType = ProtocolMessageType.getContentType(rcvRecord.getContentType()
                .getValue());
        ProtocolMessageHandler pmh = rcvRecordContentType.getProtocolMessageHandler(
                rawMessageBytes[messageParseBufferOffset], tlsContext);

        if (!pmh.isCorrectProtocolMessage(protocolMessage)) {
            protocolMessage = wrongMessageFound(pmh);
        } else {
            pmh.setProtocolMessage(protocolMessage);
        }

        messageParseBufferOffset = pmh.parseMessage(rawMessageBytes, messageParseBufferOffset);

        LOG.log(Level.FINE, "The following message was parsed: {}", pmh.getProtocolMessage().toString());

        switch (protocolMessage.getProtocolMessageType()) {
            case ALERT:
                if (isIncomingAlertFatal(pmh) && !tlsContext.isFuzzingMode()) {
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

    private boolean isIncomingAlertFatal(ProtocolMessageHandler pmh) {
        AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
        if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
            return false;
        }

        return true;
    }

    private ProtocolMessage wrongMessageFound(ProtocolMessageHandler pmh) {
        LOG.log(Level.FINE,
                "The configured protocol message is not equal to the message being parsed or the message was not found.");
        pmh.initializeProtocolMessage();
        ProtocolMessage pm = pmh.getProtocolMessage();
        return pm;
    }

    protected DtlsRecord getHandshakeMessage() {
        DtlsRecord rcvRecord;
        DtlsRecord outRecord = new DtlsRecord();
        ProtocolMessageType rcvRecordProtocolMessageType;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;
        boolean messageAvailable = false;
        byte[] rawMessageBytes;

        while (!messageAvailable && System.currentTimeMillis() <= endTimeMillies) {
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

    protected DtlsRecord getNonHandshakeNonCcsMessages() {
        DtlsRecord rcvRecord;
        ProtocolMessageType rcvRecordProtocolMessageType = null;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;

        while ((rcvRecordProtocolMessageType == ProtocolMessageType.HANDSHAKE || rcvRecordProtocolMessageType == ProtocolMessageType.CHANGE_CIPHER_SPEC)
                && (System.currentTimeMillis() <= endTimeMillies)) {
            try {
                rcvRecord = receiveNextValidRecord();
            } catch (IOException e) {
                continue;
            }
            rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord.getContentType().getValue());
            switch (rcvRecordProtocolMessageType) {
                case HANDSHAKE:
                    handshakeFragmentHandler.processHandshakeRecord(rcvRecord);
                    break;
                case CHANGE_CIPHER_SPEC:
                    processChangeCipherSpecRecord(rcvRecord);
                    break;
                default:
                    return rcvRecord;
            }
        }
        return null;
    }

    protected DtlsRecord getChangeCipherSpecMessage() {
        DtlsRecord rcvRecord;
        ProtocolMessageType rcvRecordProtocolMessageType;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;

        while (!changeCipherSpecReceived() && (System.currentTimeMillis() <= endTimeMillies)) {
            try {
                rcvRecord = receiveNextValidRecord();
            } catch (Exception e) {
                continue;
            }
            rcvRecordProtocolMessageType = ProtocolMessageType.getContentType(rcvRecord.getContentType().getValue());
            switch (rcvRecordProtocolMessageType) {
                case CHANGE_CIPHER_SPEC:
                    processChangeCipherSpecRecord(rcvRecord);
                    break;
                case HANDSHAKE:
                    handshakeFragmentHandler.processHandshakeRecord(rcvRecord);
                    break;
                case ALERT:
                    return rcvRecord;
                default:
                    break;
            }
        }
        if (changeCipherSpecReceived()) {
            return getReceivedChangeCipherSepc();
        }
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

    private DtlsRecord receiveNextValidRecord() throws IOException {
        de.rub.nds.tlsattacker.dtls.record.DtlsRecord nextRecord = receiveNextRecord();
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

    private boolean checkRecordValidity(DtlsRecord record) {
        return record.getEpoch().getValue() == serverEpochCounter;
    }

    private void processNextPacket() throws IOException {
        recordBuffer = recordHandler.parseRecords(receiveNextPacket());
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

    // private void handleRetransmit() throws IOException
    // {
    // int currentPointer;
    // byte[] retransmittedMessage;
    // LinkedList<de.rub.nds.tlsattacker.tls.record.Record> recordList = new
    // LinkedList<>();
    //
    // if (retransmitEpoch < recordHandler.getEpoch())
    // {
    // recordHandler.revertEpoch();
    // }
    //
    // for (int i = 0; i < retransmitList.size(); i++)
    // {
    // recordList.add(new DtlsRecord());
    // retransmittedMessage = retransmitList.get(i);
    // currentPointer = retransmitPointer - (retransmitList.size() - i);
    //
    // if (retransmittedMessage.length == 1)
    // {
    // bufferSendData(recordHandler.wrapData(retransmittedMessage,
    // ProtocolMessageType.CHANGE_CIPHER_SPEC,
    // recordList));
    // if (handlingMyLastProtocolMessage(protocolMessages,
    // currentMessagePointer))
    // {
    // sendBufferedData();
    // }
    // }
    // else if (retransmittedMessage.length > 2)
    // {
    // bufferSendData(recordHandler.wrapData(retransmittedMessage,
    // ProtocolMessageType.HANDSHAKE, recordList));
    // if (handlingMyLastProtocolMessage(protocolMessages,
    // currentMessagePointer))
    // {
    // sendBufferedData();
    // }
    // }
    // else
    // {
    // LOG.log(Level.SEVERE,"Empty retransmit message bytes");
    // }
    // recordList.removeFirst();
    // }
    // retransmitCounter++;
    // }
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
        retransmitEpoch = recordHandler.getEpoch();
        retransmitList.clear();
    }

    private static final Logger LOG = Logger.getLogger(DTLSActionExecutor.class.getName());

}
