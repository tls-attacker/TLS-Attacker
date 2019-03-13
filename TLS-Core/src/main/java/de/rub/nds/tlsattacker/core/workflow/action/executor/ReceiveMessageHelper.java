/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.dtls.FragmentManager;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestHandler;
import de.rub.nds.tlsattacker.core.https.HttpsResponseHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DtlsHandshakeMessageFragmentHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ParserResult;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReceiveMessageHelper() {
    }

    public MessageActionResult receiveMessages(TlsContext context) {
        return receiveMessages(new LinkedList<ProtocolMessage>(), context);
    }

    /**
     * Receives messages, and tries to receive the messages specified in
     * messages
     *
     * @param expectedMessages
     *            Messages which should be received
     * @param context
     *            The context on which Messages should be received
     * @return Actually received Messages
     */
    public MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages, TlsContext context) {
        context.setTalkingConnectionEndType(context.getChooser().getMyConnectionPeer());
        MessageActionResult result = new MessageActionResult();

        try {
            byte[] receivedBytes;
            boolean shouldContinue = true;
            do {
                receivedBytes = receiveByteArray(context);
                MessageActionResult tempResult = handleReceivedBytes(receivedBytes, context);
                result = result.merge(tempResult);
                if (receivedBytes.length != 0) {
                    if (context.getConfig().isQuickReceive() && !expectedMessages.isEmpty()) {
                        shouldContinue = shouldContinue(expectedMessages, result.getMessageList(), context);

                    }
                }
            } while (receivedBytes.length != 0 && shouldContinue);

        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while recieving for Messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }

        return result;
    }

    public MessageActionResult receiveMessagesTill(ProtocolMessage waitTillMessage, TlsContext context) {
        context.setTalkingConnectionEndType(context.getChooser().getMyConnectionPeer());
        MessageActionResult result = new MessageActionResult();
        try {
            byte[] receivedBytes;
            boolean shouldContinue = true;
            do {
                receivedBytes = receiveByteArray(context);
                MessageActionResult tempResult = handleReceivedBytes(receivedBytes, context);
                result = result.merge(tempResult);
                for (ProtocolMessage message : result.getMessageList()) {
                    if (message.getClass().equals(waitTillMessage.getClass())) {
                        LOGGER.debug("Received message we waited for");
                        shouldContinue = false;
                        break;
                    }
                }
            } while (receivedBytes.length != 0 && shouldContinue);
        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while recieving for Messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }
        return result;
    }

    public MessageActionResult handleReceivedBytes(byte[] receivedBytes, TlsContext context) {
        List<AbstractRecord> records = new LinkedList<>();
        List<ProtocolMessage> messages = new LinkedList<>();
        List<ProtocolMessage> messageFragments = new LinkedList<>();
        if (receivedBytes.length > 0) {
            List<AbstractRecord> tempRecords = parseRecords(receivedBytes, context);
            records.addAll(tempRecords);
            List<List<AbstractRecord>> recordGroups = getRecordGroups(tempRecords);
            for (List<AbstractRecord> recordGroup : recordGroups) {
                processRecordGroup(recordGroup, context, messageFragments, messages);
            }
        }

        return new MessageActionResult(records, messages, messageFragments);
    }

    private void processRecordGroup(List<AbstractRecord> recordGroup, TlsContext context,
    // OUT params
            List<ProtocolMessage> messageFragments, List<ProtocolMessage> messages) {

        adjustContext(recordGroup, context);
        decryptRecords(recordGroup, context);

        List<ProtocolMessage> processedMessages = null;

        if (!context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            processedMessages = parseMessages(recordGroup, context);
        } else {
            byte[] cleanBytes = getCleanBytes(recordGroup);
            List<ProtocolMessage> processedFragments = handleFragments(cleanBytes, recordGroup.get(0)
                    .getContentMessageType(), context);
            messageFragments.addAll(processedFragments);
            processedMessages = processFragmentGroup(processedFragments, context);
        }

        messages.addAll(processedMessages);

    }

    public List<AbstractRecord> receiveRecords(TlsContext context) {
        context.setTalkingConnectionEndType(context.getChooser().getMyConnectionPeer());
        List<AbstractRecord> realRecords = new LinkedList<>();
        try {
            byte[] receivedBytes;
            do {
                receivedBytes = receiveByteArray(context);
                if (receivedBytes.length != 0) {
                    List<AbstractRecord> tempRecords = parseRecords(receivedBytes, context);
                    realRecords.addAll(tempRecords);
                }
            } while (receivedBytes.length != 0);

        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while recieving for Messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }
        return realRecords;
    }

    private boolean receivedFatalAlert(List<ProtocolMessage> messages) {
        for (ProtocolMessage message : messages) {
            if (message instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) message;
                if (alert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean receivedAllExpectedMessage(List<ProtocolMessage> expectedMessages,
            List<ProtocolMessage> actualMessages, boolean earlyStop) {
        if (actualMessages.size() != expectedMessages.size() && !earlyStop) {
            return false;
        } else {
            for (int i = 0; i < expectedMessages.size(); i++) {
                if (i >= actualMessages.size()) {
                    return false;
                }
                if (!expectedMessages.get(i).getClass().equals(actualMessages.get(i).getClass())) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean shouldContinue(List<ProtocolMessage> expectedMessages, List<ProtocolMessage> receivedMessages,
            TlsContext context) {

        boolean receivedFatalAlert = receivedFatalAlert(receivedMessages);
        if (receivedFatalAlert) {
            return false;
        }
        boolean receivedAllExpectedMessages = receivedAllExpectedMessage(expectedMessages, receivedMessages, context
                .getConfig().isEarlyStop());
        return !receivedAllExpectedMessages;
    }

    private byte[] receiveByteArray(TlsContext context) throws IOException {
        byte[] received = context.getTransportHandler().fetchData();
        return received;
    }

    private List<AbstractRecord> parseRecords(byte[] recordBytes, TlsContext context) {
        try {
            return context.getRecordLayer().parseRecords(recordBytes);
        } catch (ParserException ex) {
            LOGGER.debug(ex);
            LOGGER.debug("Could not parse provided Bytes into records. Waiting for more Packets");
            byte[] extraBytes = new byte[0];
            try {
                extraBytes = receiveByteArray(context);
            } catch (IOException ex2) {
                LOGGER.warn("Could not receive more Bytes", ex2);
                context.setReceivedTransportHandlerException(true);
            }
            if (extraBytes != null && extraBytes.length > 0) {
                return parseRecords(ArrayConverter.concatenate(recordBytes, extraBytes), context);
            }
            LOGGER.debug("Did not receive more Bytes. Parsing records softly");
            return context.getRecordLayer().parseRecordsSoftly(recordBytes);
        }
    }

    public List<ProtocolMessage> parseMessages(List<AbstractRecord> records, TlsContext context) {
        byte[] cleanProtocolMessageBytes = getCleanBytes(records);
        // Due to TLS 1.3 Encrypted Type it might be necessary to look for
        // new groups here
        List<ProtocolMessage> messages = new LinkedList<>();
        for (List<AbstractRecord> subgroup : getRecordGroups(records)) {
            messages.addAll((handleCleanBytes(cleanProtocolMessageBytes, getProtocolMessageType(subgroup), context)));
        }
        return messages;
    }

    private List<ProtocolMessage> handleCleanBytes(byte[] cleanProtocolMessageBytes,
            ProtocolMessageType typeFromRecord, TlsContext context) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        while (dataPointer < cleanProtocolMessageBytes.length) {
            if (isZeroPadding(cleanProtocolMessageBytes, dataPointer)) {
                break;
            }
            ParserResult result = null;
            try {
                if (typeFromRecord != null) {
                    if (typeFromRecord == ProtocolMessageType.APPLICATION_DATA
                            && context.getConfig().isHttpsParsingEnabled()) {
                        try {
                            result = tryHandleAsHttpsMessage(cleanProtocolMessageBytes, dataPointer, context);
                        } catch (ParserException | AdjustmentException | UnsupportedOperationException E) {
                            result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                    context, false);
                        }
                    } else {
                        result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                context, false);
                    }
                } else {
                    if (cleanProtocolMessageBytes.length > 2) {
                        result = tryHandleAsSslMessage(cleanProtocolMessageBytes, dataPointer, context);
                    } else {
                        result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context);
                    }
                }
            } catch (ParserException | AdjustmentException | UnsupportedOperationException exCorrectMsg) {
                LOGGER.warn("Could not parse Message as a CorrectMessage");
                LOGGER.debug(exCorrectMsg);
                try {
                    if (typeFromRecord == ProtocolMessageType.HANDSHAKE) {
                        LOGGER.warn("Trying to parse Message as UnknownHandshakeMessage");
                        result = tryHandleAsUnknownHandshakeMessage(cleanProtocolMessageBytes, dataPointer,
                                typeFromRecord, context);
                    } else {
                        try {
                            result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context);
                        } catch (ParserException | AdjustmentException | UnsupportedOperationException exUnknownHMsg) {
                            LOGGER.warn("Could not parse Message as UnknownMessage");
                            LOGGER.debug(exUnknownHMsg);
                            break;
                        }
                    }
                } catch (ParserException | UnsupportedOperationException exUnknownHandshakeMsg) {
                    LOGGER.warn("Could not parse Message as UnknownHandshakeMessage");
                    LOGGER.debug(exUnknownHandshakeMsg);

                    try {
                        result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context);
                    } catch (ParserException | AdjustmentException | UnsupportedOperationException exUnknownHMsg) {
                        LOGGER.warn("Could not parse Message as UnknownMessage");
                        LOGGER.debug(exUnknownHMsg);
                        break;
                    }
                }
            }
            if (result != null) {
                if (dataPointer == result.getParserPosition()) {
                    throw new ParserException("Ran into an infinite loop while parsing ProtocolMessages");
                }
                dataPointer = result.getParserPosition();
                LOGGER.debug("The following message was parsed: {}", result.getMessage().toString());
                receivedMessages.add(result.getMessage());
            }
        }
        return receivedMessages;
    }

    private List<ProtocolMessage> handleFragments(byte[] cleanProtocolMessageBytes, ProtocolMessageType typeFromRecord,
            TlsContext context) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedFragmentMessages = new LinkedList<>();
        while (dataPointer < cleanProtocolMessageBytes.length) {
            if (isZeroPadding(cleanProtocolMessageBytes, dataPointer)) {
                break;
            }
            ParserResult result = null;
            try {
                if (typeFromRecord == ProtocolMessageType.HANDSHAKE) {
                    result = tryParseAsDtlsMessageFragment(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                            context);
                } else {
                    result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord, context,
                            false);
                }
            } catch (ParserException | AdjustmentException exCorrectMsg) {
                LOGGER.warn("Could not parse Message as a DtlsMessageFragment/NonHsMessage");
                LOGGER.debug(exCorrectMsg);
                try {
                    result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context);
                } catch (ParserException exUnknownMsg) {
                    LOGGER.warn("Could not parse Message as UnknownMessage");
                    LOGGER.debug(exUnknownMsg);
                    break;
                }
            }
            if (result != null) {
                if (dataPointer == result.getParserPosition()) {
                    throw new ParserException("Ran into an infinite loop while parsing ProtocolMessages");
                }
                dataPointer = result.getParserPosition();
                // NOTE: not a retransmission
                if (result.getMessage() != null) {
                    LOGGER.debug("The following message was parsed: {}", result.getMessage().toString());
                    receivedFragmentMessages.add(result.getMessage());
                }
            }
        }
        return receivedFragmentMessages;
    }

    // check needed for some implementations (i.e. OpenSSL 0.9.8h on Windows)
    private boolean isZeroPadding(byte[] protocolMessageBytes, int dataPointer) {
        for (int i = dataPointer; i < protocolMessageBytes.length; i++) {
            if (protocolMessageBytes[i] != 0)
                return false;
        }
        return true;
    }

    private ParserResult tryHandleAsHttpsMessage(byte[] protocolMessageBytes, int pointer, TlsContext context)
            throws ParserException, AdjustmentException {
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            HttpsRequestHandler handler = new HttpsRequestHandler(context);
            return handler.parseMessage(protocolMessageBytes, pointer, false);
        } else {
            HttpsResponseHandler handler = new HttpsResponseHandler(context);
            return handler.parseMessage(protocolMessageBytes, pointer, false);
        }
    }

    private ParserResult tryHandleAsCorrectMessage(byte[] protocolMessageBytes, int pointer,
            ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse) throws ParserException,
            AdjustmentException {
        HandshakeMessageType handshakeMessageType = HandshakeMessageType.getMessageType(protocolMessageBytes[pointer]);
        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, handshakeMessageType);
        return pmh.parseMessage(protocolMessageBytes, pointer, onlyParse);
    }

    /*
     * @return ParserResult, if the message is null it should be ignored.
     */
    private ParserResult tryParseAsDtlsMessageFragment(byte[] protocolMessageBytes, int pointer,
            ProtocolMessageType typeFromRecord, TlsContext context) throws ParserException, AdjustmentException {
        DtlsHandshakeMessageFragmentHandler fragmentHandler = new DtlsHandshakeMessageFragmentHandler(context);
        return fragmentHandler.parseMessage(protocolMessageBytes, pointer, false);
    }

    private ParserResult tryHandleAsSslMessage(byte[] cleanProtocolMessageBytes, int dataPointer, TlsContext context) {
        // TODO: SSL2 ServerVerify messages have their message type encrypted -
        // it's up to the client to know what to expect next. Is this good
        // enough?
        HandshakeMessageHandler<? extends SSL2HandshakeMessage> handler;
        if (cleanProtocolMessageBytes[2] == HandshakeMessageType.SSL2_SERVER_HELLO.getValue()) {
            handler = new SSL2ServerHelloHandler(context);
        } else {
            handler = new SSL2ServerVerifyHandler(context);
        }
        return handler.parseMessage(cleanProtocolMessageBytes, dataPointer, false);
    }

    private ParserResult tryHandleAsUnknownHandshakeMessage(byte[] protocolMessageBytes, int pointer,
            ProtocolMessageType typeFromRecord, TlsContext context) throws ParserException, AdjustmentException {
        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, HandshakeMessageType.UNKNOWN);
        return pmh.parseMessage(protocolMessageBytes, pointer, false);
    }

    private ParserResult tryHandleAsUnknownMessage(byte[] protocolMessageBytes, int pointer, TlsContext context)
            throws ParserException, AdjustmentException {
        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, ProtocolMessageType.UNKNOWN, null);
        return pmh.parseMessage(protocolMessageBytes, pointer, false);
    }

    private byte[] getCleanBytes(List<AbstractRecord> recordSubGroup) {
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

    private List<List<AbstractRecord>> getRecordGroups(List<AbstractRecord> records) {
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

    private ProtocolMessageType getProtocolMessageType(List<AbstractRecord> recordSubGroup) {
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

    private void decryptRecords(List<AbstractRecord> records, TlsContext context) {
        for (AbstractRecord record : records) {
            context.getRecordLayer().decryptRecord(record);
        }
    }

    private void adjustContext(List<AbstractRecord> recordGroup, TlsContext context) {
        for (AbstractRecord record : recordGroup) {
            record.adjustContext(context);
        }
    }

    private List<ProtocolMessage> processFragmentGroup(List<ProtocolMessage> fragmentedMessages, TlsContext context) {
        List<ProtocolMessage> realMessages = new LinkedList<>();
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        ProtocolMessageType lastRecordType = null;
        for (ProtocolMessage message : fragmentedMessages) {
            if (lastRecordType == null) {
                lastRecordType = message.getProtocolMessageType();
            }
            if (message instanceof DtlsHandshakeMessageFragment) {
                fragments.add((DtlsHandshakeMessageFragment) message);
            } else {
                message.getHandler(context).prepareAfterParse(message);
                message.getHandler(context).adjustTLSContext(message);
                realMessages.add(message);
            }
            lastRecordType = message.getProtocolMessageType();
        }
        List<ProtocolMessage> messagesFromFragments = processDtlsFragments(fragments, context);
        realMessages.addAll(messagesFromFragments);

        return realMessages;
    }

    /*
     * Processes a list of arbitrary-ordered fragments. The idea is: 1. we
     * assemble fragments into "fragmented messages" 2. we extract the messages
     * from fragments but only update the context for fragments whose message
     * sequence is next for processing.
     */
    private List<ProtocolMessage> processDtlsFragments(List<DtlsHandshakeMessageFragment> fragments, TlsContext context) {
        // the fragment manager stores all the received message fragments
        FragmentManager manager = context.getFragmentManager();
        List<ProtocolMessage> messages = new LinkedList<>();

        // we first add the fragments to the manager
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            manager.addMessageFragment(fragment);
        }

        // we then process all the fragmented messages with increasing message
        // seq
        // until we until we arrive at a message seq for which no fragmented
        // message was formed
        DtlsHandshakeMessageFragment fragmentedMessage = manager.getFragmentedMessage(context
                .getNextReceiveSequenceNumber());
        while (fragmentedMessage != null) {
            context.increaseNextReceiveSequenceNumber();
            manager.clearFragmentedMessage(fragmentedMessage);
            messages.add(processFragmentedMessage(fragmentedMessage, context, true));
            fragmentedMessage = manager.getFragmentedMessage(context.getNextReceiveSequenceNumber());
        }

        // we finally process fragmented messages whose sequence number is
        // out-of-order
        // note that we do not update the TLS context for these messages, we
        // only do that
        // for in-order messages
        Set<Integer> fragmentSeq = new HashSet<Integer>();
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            fragmentedMessage = manager.getFragmentedMessage(fragment);
            if (fragmentedMessage != null && !fragmentSeq.contains(fragmentedMessage.getMessageSeq().getValue())) {
                messages.add(processFragmentedMessage(fragmentedMessage, context, false));
            }
            fragmentSeq.add(fragment.getMessageSeq().getValue());
        }

        return messages;
    }

    /*
     * Processes a fragmented message by extracting the underlying message and
     * optionally performing the corresponding context update.
     */
    private HandshakeMessage processFragmentedMessage(DtlsHandshakeMessageFragment fragment, TlsContext context,
            boolean updateContext) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(fragment.getType().getValue());
        try {
            stream.write(ArrayConverter.intToBytes(fragment.getLength().getValue(),
                    HandshakeByteLength.MESSAGE_LENGTH_FIELD));
        } catch (IOException ex) {
            LOGGER.warn("Could not write fragment to stream.", ex);
        }
        try {
            stream.write(fragment.getContent().getValue());
        } catch (IOException ex) {
            LOGGER.warn("Could not write fragment to stream.", ex);
        }

        ParserResult parsingResult = tryHandleAsCorrectMessage(stream.toByteArray(), 0,
                fragment.getProtocolMessageType(), context, true);
        HandshakeMessage message = (HandshakeMessage) parsingResult.getMessage();
        message.getHandler(context).prepareAfterParse(message);
        if (updateContext) {
            message.getHandler(context).adjustTLSContext(message);

            // TODO it is not nice that we are updating receiving digests
            // outside of the message handlers
            if (message.getIncludeInDigest()) {
                context.getDigest().append(fragment.getCompleteResultingMessage().getOriginalValue());
            }
        }

        return message;
    }
}
