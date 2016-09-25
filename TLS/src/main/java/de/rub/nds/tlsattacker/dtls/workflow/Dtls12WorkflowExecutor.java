/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.dtls.workflow;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.HandshakeFragmentHandler;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecord;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class Dtls12WorkflowExecutor extends GenericWorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(Dtls12WorkflowExecutor.class);

    private byte[] handshakeMessageSendBuffer, recordSendBuffer = new byte[0];

    private int messageParseBufferOffset, sendHandshakeMessageSeq, maxWaitForExpectedRecord = 3000, maxRetransmits = 4,
            serverEpochCounter, maxPacketSize = 1400, maxHandshakeReorderBufferSize = 100, retransmitCounter,
            retransmitPointer, retransmitEpoch;

    private final WorkflowTrace workflowTrace;

    private DtlsRecord currentRecord, changeCipherSpecRecordBuffer, parseRecordBuffer;

    private List<ProtocolMessage> protocolMessages;

    private final List<byte[]> retransmitList = new ArrayList<>();

    private List<de.rub.nds.tlsattacker.tls.record.Record> recordBuffer = new LinkedList<>(),
            handshakeMessageSendRecordList = null;

    private final HandshakeFragmentHandler handshakeFragmentHandler = new HandshakeFragmentHandler();

    private final DtlsRecordHandler dtlsRecordHandler;

    public Dtls12WorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
        super(transportHandler, tlsContext);

        tlsContext.setRecordHandler(new DtlsRecordHandler(tlsContext));

        workflowTrace = this.tlsContext.getWorkflowTrace();
        recordHandler = tlsContext.getRecordHandler();
        dtlsRecordHandler = (DtlsRecordHandler) tlsContext.getRecordHandler();

        if (this.transportHandler == null || recordHandler == null) {
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
        try {
            ProtocolMessage pm;

            while (workflowContext.getProtocolMessagePointer() < protocolMessages.size()
                    && workflowContext.isProceedWorkflow() && retransmitCounter < maxRetransmits) {
                pm = getWorkflowProtocolMessage(workflowContext.getProtocolMessagePointer());
                updateFlight(pm);
                if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
                    handleMyProtocolMessage(pm);
                    workflowContext.incrementProtocolMessagePointer();
                } else {
                    if (receiveAndParseNextProtocolMessage(pm)) {
                        workflowContext.incrementProtocolMessagePointer();
                    } else {
                        handleRetransmit();
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.info(e.getLocalizedMessage(), e);
            throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
        } finally {
            // remove all unused protocol messages
            this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
        }
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

    private void handleMyNonHandshakeMessage(ProtocolMessage protocolMessage) throws IOException {
        ProtocolMessageHandler<? extends ProtocolMessage> pmh = protocolMessage.getProtocolMessageHandler(tlsContext);

        byte[] messageBytes = pmh.prepareMessage();

        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }

        byte[] record = recordHandler.wrapData(messageBytes, protocolMessage.getProtocolMessageType(),
                protocolMessage.getRecords());

        LOGGER.debug("Sending the following protocol message to DTLS peer: {}\nRaw Bytes: {}",
                protocolMessage.getClass(), ArrayConverter.bytesToHexString(record));

        transportHandler.sendData(record);
    }

    private void handleMyChangeCipherSpecMessage(ProtocolMessage protocolMessage) throws IOException {
        ProtocolMessageHandler<? extends ProtocolMessage> pmh = protocolMessage.getProtocolMessageHandler(tlsContext);
        byte[] messageBytes = pmh.prepareMessage();

        retransmitList.add(messageBytes);

        if (protocolMessage.getRecords() == null || protocolMessage.getRecords().isEmpty()) {
            protocolMessage.addRecord(new DtlsRecord());
        }

        byte[] record = recordHandler.wrapData(messageBytes, ProtocolMessageType.CHANGE_CIPHER_SPEC,
                protocolMessage.getRecords());

        sendDataBuffered(record, workflowContext.getProtocolMessagePointer());
    }

    private void handleMyHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
        ProtocolMessageHandler<? extends ProtocolMessage> pmh = handshakeMessage.getProtocolMessageHandler(tlsContext);
        handshakeMessage.setMessageSeq(sendHandshakeMessageSeq);
        byte[] handshakeMessageBytes = pmh.prepareMessage();

        handshakeMessageSendBuffer = ArrayConverter.concatenate(handshakeMessageSendBuffer,
                handshakeFragmentHandler.fragmentHandshakeMessage(handshakeMessageBytes, maxPacketSize - 25));

        retransmitList.add(handshakeMessageSendBuffer);

        if (handshakeMessageSendRecordList == null) {
            if (handshakeMessage.getRecords() != null && !handshakeMessage.getRecords().isEmpty()) {
                handshakeMessageSendRecordList = handshakeMessage.getRecords();
            } else {
                handshakeMessageSendRecordList = new ArrayList<>();
                handshakeMessageSendRecordList.add(new DtlsRecord());
                handshakeMessage.setRecords(handshakeMessageSendRecordList);
            }
        }

        if (handlingMyLastProtocolMessageWithContentType(protocolMessages, workflowContext.getProtocolMessagePointer())) {
            sendDataBuffered(
                    recordHandler.wrapData(handshakeMessageSendBuffer, ProtocolMessageType.HANDSHAKE,
                            handshakeMessage.getRecords()), workflowContext.getProtocolMessagePointer());
            handshakeMessageSendRecordList = null;
            handshakeMessageSendBuffer = new byte[0];
        }
        sendHandshakeMessageSeq++;
    }

    private void sendDataBuffered(byte[] records, int currentMessagePointer) throws IOException {
        recordSendBuffer = ArrayConverter.concatenate(recordSendBuffer, records);
        if (handlingMyLastProtocolMessage(protocolMessages, currentMessagePointer)) {
            LOGGER.debug("Sending the following protocol messages to DTLS peer: {}",
                    ArrayConverter.bytesToHexString(recordSendBuffer));
            int pointer = 0;
            int currentRecordSize = 0;
            byte[] sendBuffer = new byte[0];

            while (pointer < recordSendBuffer.length) {
//                Causes problems when record size is explicitly set, TODO
                currentRecordSize = (recordSendBuffer[pointer + 11] << 8) + (recordSendBuffer[pointer + 12] & 0xFF)
                        + 13;
                if (currentRecordSize > (recordSendBuffer.length - pointer) || currentRecordSize < 0 ) {
                    currentRecordSize = recordSendBuffer.length - pointer;
                }
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
    }

    private DtlsRecord getNextProtocolMessageRecord(ProtocolMessage pm) throws Exception {
        switch (pm.getProtocolMessageType()) {
            case HANDSHAKE:
                return getHandshakeMessage();
            case CHANGE_CIPHER_SPEC:
                return getChangeCipherSpecMessage();
            default:
                return getNonHandshakeNonCcsMessages();
        }
    }

    private boolean receiveAndParseNextProtocolMessage(ProtocolMessage pm) throws Exception {
        DtlsRecord rcvRecord = parseRecordBuffer;

        if (rcvRecord == null) {
            rcvRecord = getNextProtocolMessageRecord(pm);
            if (rcvRecord == null) {
                return false;
            }
        }

        byte[] rawMessageBytes = rcvRecord.getProtocolMessageBytes().getValue();
        ProtocolMessageType rcvRecordContentType = ProtocolMessageType.getContentType(rcvRecord.getContentType()
                .getValue());
        ProtocolMessageHandler pmh = rcvRecordContentType.getProtocolMessageHandler(
                rawMessageBytes[messageParseBufferOffset], tlsContext);

        if (!pmh.isCorrectProtocolMessage(pm)) {
            pm = wrongMessageFound(pmh);
        } else {
            pmh.setProtocolMessage(pm);
        }

        messageParseBufferOffset = pmh.parseMessage(rawMessageBytes, messageParseBufferOffset);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
        }

        switch (pm.getProtocolMessageType()) {
            case ALERT:
                handleIncomingAlert(pmh);
                break;
            case HANDSHAKE:
                handshakeFragmentHandler.addRecordsToHandshakeMessage(pm);
                handshakeFragmentHandler.incrementExpectedHandshakeMessageSeq();
                break;
            case CHANGE_CIPHER_SPEC:
                serverEpochCounter++;
                pm.addRecord(currentRecord);
                break;
            default:
                pm.addRecord(currentRecord);
        }

        if (messageParseBufferOffset >= rawMessageBytes.length) {
            parseRecordBuffer = null;
            messageParseBufferOffset = 0;
        } else {
            parseRecordBuffer = rcvRecord;
        }
        return true;
    }

    private ProtocolMessage getWorkflowProtocolMessage(int messagePointer) {
        if (messagePointer < protocolMessages.size()) {
            return protocolMessages.get(messagePointer);
        }
        return null;
    }

    private boolean handleIncomingAlert(ProtocolMessageHandler pmh) {
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
        removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
        pmh.initializeProtocolMessage();
        ProtocolMessage pm = pmh.getProtocolMessage();
        protocolMessages.add(pm);
        return pm;
    }

    protected DtlsRecord getHandshakeMessage() throws Exception {
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
            } catch (Exception e) {
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

    protected DtlsRecord getNonHandshakeNonCcsMessages() throws Exception {
        DtlsRecord rcvRecord;
        ProtocolMessageType rcvRecordProtocolMessageType = null;
        long endTimeMillies = System.currentTimeMillis() + maxWaitForExpectedRecord;

        while ((rcvRecordProtocolMessageType == ProtocolMessageType.HANDSHAKE || rcvRecordProtocolMessageType == ProtocolMessageType.CHANGE_CIPHER_SPEC)
                && (System.currentTimeMillis() <= endTimeMillies)) {
            try {
                rcvRecord = receiveNextValidRecord();
            } catch (Exception e) {
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

    protected DtlsRecord getChangeCipherSpecMessage() throws Exception {
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
        if (this.maxPacketSize > 16397) {
            this.maxPacketSize = 16397;
        } else {
            this.maxPacketSize = maxPacketSize;
        }
    }

    private boolean isHandshakeOrCCS(ProtocolMessageType pmt) {
        return pmt == ProtocolMessageType.HANDSHAKE || pmt == ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    private void handleRetransmit() throws IOException {
        int currentPointer;
        byte[] retransmittedMessage;
        LinkedList<de.rub.nds.tlsattacker.tls.record.Record> recordList = new LinkedList<>();

        if (retransmitEpoch < dtlsRecordHandler.getEpoch()) {
            dtlsRecordHandler.revertEpoch();
        }

        for (int i = 0; i < retransmitList.size(); i++) {
            recordList.add(new DtlsRecord());
            retransmittedMessage = retransmitList.get(i);
            currentPointer = retransmitPointer - (retransmitList.size() - i);

            if (retransmittedMessage.length == 1) {
                sendDataBuffered(recordHandler.wrapData(retransmittedMessage, ProtocolMessageType.CHANGE_CIPHER_SPEC,
                        recordList), currentPointer);
            } else if (retransmittedMessage.length > 2) {
                sendDataBuffered(
                        recordHandler.wrapData(retransmittedMessage, ProtocolMessageType.HANDSHAKE, recordList),
                        currentPointer);
            } else {
                LOGGER.error("Empty retransmit message bytes");
            }
            recordList.removeFirst();
        }
        retransmitCounter++;
    }

    private int getNextHandshakeMessageNotFromMe(int currentProtocolMessage, List<ProtocolMessage> protocolMessageList,
            ConnectionEnd myEnd) {
        if (currentProtocolMessage > (protocolMessageList.size() - 2)) {
            // If the current message is the last message, return immediately
            return -1;
        }

        int output;
        boolean found = false;
        ProtocolMessage currentMessage;

        for (output = currentProtocolMessage + 1; output < protocolMessageList.size(); output++) {
            currentMessage = protocolMessageList.get(output);
            if (isHandshakeOrCCS(currentMessage.getProtocolMessageType())) {
                if (currentMessage.getMessageIssuer() != myEnd) {
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            return -1;
        } else {
            return output;
        }
    }

    private void updateFlight(ProtocolMessage pm) {
        if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
            if (workflowContext.getProtocolMessagePointer() > 1) {
                ProtocolMessage lastPM = protocolMessages.get(workflowContext.getProtocolMessagePointer() - 1);

                if (isHandshakeOrCCS(pm.getProtocolMessageType())) {
                    if ((lastPM.getMessageIssuer() != tlsContext.getMyConnectionEnd() || !isHandshakeOrCCS(lastPM
                            .getProtocolMessageType()))
                            && workflowContext.getProtocolMessagePointer() > retransmitPointer) {
                        flightTransition();
                    }
                }
            } else {
                flightTransition();
            }
        }
    }

    private void flightTransition() {
        retransmitPointer = getNextHandshakeMessageNotFromMe(workflowContext.getProtocolMessagePointer(),
                protocolMessages, tlsContext.getMyConnectionEnd());
        retransmitCounter = 0;
        retransmitEpoch = dtlsRecordHandler.getEpoch();
        retransmitList.clear();
    }
}
