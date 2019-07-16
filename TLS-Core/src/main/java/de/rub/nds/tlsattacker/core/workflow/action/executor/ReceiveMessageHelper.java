/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
                if (context.getConfig().isQuickReceive() && !expectedMessages.isEmpty()) {
                    shouldContinue = shouldContinue(expectedMessages, result.getMessageList(), context);
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
        MessageActionResult result = new MessageActionResult();
        if (receivedBytes.length > 0) {
            List<AbstractRecord> tempRecords = parseRecords(receivedBytes, context);
            List<RecordGroup> recordGroups = RecordGroup.generateRecordGroups(tempRecords, context);
            for (RecordGroup recordGroup : recordGroups) {
                MessageActionResult tempResult = processRecordGroup(recordGroup, context);
                result = result.merge(tempResult);
            }
        }

        return result;
    }

    private MessageActionResult processRecordGroup(RecordGroup recordGroup, TlsContext context) {
        recordGroup.adjustContext(context);
        recordGroup.decryptRecords(context);

        MessageParsingResult messageParsingResult = parseMessages(recordGroup, context);

        return new MessageActionResult(recordGroup.getRecords(), messageParsingResult.getMessages(),
                messageParsingResult.getMessageFragments());
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
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while recieving for Messages.", ex);
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

    public MessageParsingResult parseMessages(RecordGroup recordGroup, TlsContext context) {
        byte[] cleanProtocolMessageBytes = recordGroup.getCleanBytes();
        // Due to TLS 1.3 Encrypted Type it might be necessary to look for
        // new groups here
        List<ProtocolMessage> messages = new LinkedList<>();
        List<DtlsHandshakeMessageFragment> messageFragments = new LinkedList<>();
        for (RecordGroup group : RecordGroup.generateRecordGroups(recordGroup.getRecords(), context)) {

            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                // if the protocol is DTLS, parsing HANDSHAKE messages results
                // in fragments.
                if (group.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
                    List<ProtocolMessage> parsedMessages = handleCleanBytes(cleanProtocolMessageBytes,
                            group.getProtocolMessageType(), context, true, true);
                    for (ProtocolMessage parsedMessage : parsedMessages) {
                        // we need this check since there might be
                        // "unknown messages", note, we do not maintain ordering
                        // between fragment and non-fragment messages
                        if (parsedMessage.isDtlsHandshakeMessageFragment()) {
                            messageFragments.add((DtlsHandshakeMessageFragment) parsedMessage);
                        } else {
                            messages.add(parsedMessage);
                        }
                    }
                    List<ProtocolMessage> parsedFragmentedMessages = processDtlsFragments(messageFragments,
                            recordGroup.getDtlsEpoch(), context);
                    messages.addAll(parsedFragmentedMessages);
                } else {
                    boolean isInOrder = recordGroup.getDtlsEpoch() == context.getDtlsNextReceiveEpoch();
                    // we only update the context for in order records (with
                    // epoch == current) unless the update on ooo was set, in
                    // which case we always update
                    boolean onlyParse = isInOrder ? false : context.getConfig().isDtlsUpdateOnOutOfOrder() ? false
                            : true;
                    List<ProtocolMessage> parsedMessages = handleCleanBytes(cleanProtocolMessageBytes,
                            group.getProtocolMessageType(), context, onlyParse, false);
                    if (isInOrder || !context.getConfig().isDtlsExcludeOutOfOrder()) {
                        messages.addAll(parsedMessages);
                    }
                }
            } else {
                List<ProtocolMessage> parsedMessages = handleCleanBytes(cleanProtocolMessageBytes,
                        group.getProtocolMessageType(), context, false, false);
                messages.addAll(parsedMessages);
            }
        }
        return new MessageParsingResult(messages, messageFragments);
    }

    private List<ProtocolMessage> handleCleanBytes(byte[] cleanProtocolMessageBytes,
            ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse,
            boolean handleHandshakeAsDtlsFragments) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        while (dataPointer < cleanProtocolMessageBytes.length) {
            ParserResult result = null;
            try {
                if (typeFromRecord != null) {
                    if (typeFromRecord == ProtocolMessageType.APPLICATION_DATA
                            && context.getConfig().isHttpsParsingEnabled()) {
                        try {
                            result = tryHandleAsHttpsMessage(cleanProtocolMessageBytes, dataPointer, context);
                        } catch (ParserException | AdjustmentException | UnsupportedOperationException E) {
                            result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                    context, onlyParse, handleHandshakeAsDtlsFragments);
                        }
                    } else {
                        result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                context, onlyParse, handleHandshakeAsDtlsFragments);
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
            ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse,
            boolean handleHandshakeAsDtlsFragments) throws ParserException, AdjustmentException {
        ProtocolMessageHandler pmh = null;
        if (typeFromRecord == ProtocolMessageType.HANDSHAKE && handleHandshakeAsDtlsFragments) {
            pmh = new DtlsHandshakeMessageFragmentHandler(context);
        } else if (typeFromRecord == ProtocolMessageType.UNKNOWN) {
            return tryHandleAsSslMessage(protocolMessageBytes, pointer, context);
        } else {
            HandshakeMessageType handshakeMessageType = HandshakeMessageType
                    .getMessageType(protocolMessageBytes[pointer]);
            pmh = HandlerFactory.getHandler(context, typeFromRecord, handshakeMessageType);
        }
        return pmh.parseMessage(protocolMessageBytes, pointer, onlyParse);
    }

    private ParserResult tryHandleAsSslMessage(byte[] cleanProtocolMessageBytes, int dataPointer, TlsContext context) {
        // TODO: SSL2 ServerVerify messages have their message type encrypted -
        // it's up to the client to know what to expect next. Is this good
        // enough?
        HandshakeMessageHandler<? extends SSL2HandshakeMessage> handler;
        int typeOffset = 2;
        // SSL2 Long length field?
        if ((cleanProtocolMessageBytes[dataPointer] & (byte) 0x80) == 0) {
            LOGGER.debug("Long SSL2 length field detected");
            typeOffset++;
        } else {
            LOGGER.debug("Normal SSL2 length field detected");
        }
        if (cleanProtocolMessageBytes.length < dataPointer + typeOffset) {
            throw new ParserException("Cannot parse cleanBytes as SSL2 messages. Not enough data present");
        }

        if (cleanProtocolMessageBytes[dataPointer + typeOffset] == HandshakeMessageType.SSL2_SERVER_HELLO.getValue()) {
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

    /*
     * Processes a list of arbitrary-ordered fragments. The idea is: 1. we
     * assemble fragments into "fragmented messages", which are fragments
     * carrying each a single handshake message. 2. we extract the messages from
     * fragments but only update the context for fragments whose message
     * sequence is next for processing.
     */
    private List<ProtocolMessage> processDtlsFragments(List<DtlsHandshakeMessageFragment> fragments, Integer epoch,
            TlsContext context) {

        // the fragment manager stores all the message fragments received
        FragmentManager manager = context.getDtlsFragmentManager();
        List<ProtocolMessage> messages = new LinkedList<>();

        for (DtlsHandshakeMessageFragment fragment : fragments) {

            // we first add the fragment to the manager
            manager.addMessageFragment(fragment, epoch);

            // we retrieve the corresponding fragmented message (or null if the
            // message is incomplete)
            DtlsHandshakeMessageFragment fragmentedMessage = manager.getFragmentedMessage(fragment.getMessageSeq()
                    .getValue(), epoch);

            // we only act if the addition of the fragment completed the
            // fragmented message
            // meaning a handshake message can be parsed from it
            if (fragmentedMessage != null) {
                context.setDtlsCurrentReceiveSequenceNumber(fragmentedMessage.getMessageSeq().getValue());

                // we check if the assembled fragment is in-order, and if so,
                // process it (aka parse message, add it to list, remove
                // fragment
                // from manager) and update the context
                if (epoch == context.getDtlsNextReceiveEpoch()
                        && fragment.getMessageSeq().getValue() == context.getDtlsNextReceiveSequenceNumber()) {
                    manager.clearFragmentedMessage(fragmentedMessage.getMessageSeq().getValue(), epoch);
                    HandshakeMessage message = processFragmentedMessage(fragmentedMessage, context, true);
                    messages.add(message);
                    if (message.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {
                        context.setDtlsNextReceiveSequenceNumber(0);
                    } else {
                        context.increaseDtlsNextReceiveSequenceNumber();
                    }
                }

                // if the fragment is out of order we only process it but DO NOT
                // update the context unless explicitly configured. we also
                // handle
                // the dtlsExcludeOutOfOrder option which allows TLS-Attacker to
                // omit messages out-of-order
                else {
                    HandshakeMessage message = processFragmentedMessage(fragmentedMessage, context, context.getConfig()
                            .isDtlsUpdateOnOutOfOrder());
                    manager.clearFragmentedMessage(fragmentedMessage.getMessageSeq().getValue(), epoch);
                    if (!context.getConfig().isDtlsExcludeOutOfOrder()) {
                        messages.add(message);
                    }
                }
            }
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
            stream.write(fragment.getContent().getValue());
        } catch (IOException ex) {
            LOGGER.warn("Could not write fragment to stream.", ex);
        }
        ParserResult parsingResult = tryHandleAsCorrectMessage(stream.toByteArray(), 0,
                fragment.getProtocolMessageType(), context, !updateContext, false);
        HandshakeMessage message = (HandshakeMessage) parsingResult.getMessage();

        return message;
    }
}
