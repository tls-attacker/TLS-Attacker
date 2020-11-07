/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.exceptions.UnsortableRecordsExceptions;
import de.rub.nds.tlsattacker.core.https.HttpsRequestHandler;
import de.rub.nds.tlsattacker.core.https.HttpsResponseHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DtlsHandshakeMessageFragmentHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ParserResult;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Comparator;
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
     * Messages which should be received
     * @param context
     * The context on which Messages should be received
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
                    shouldContinue =
                        testIfWeShouldContinueToReceive(expectedMessages, result.getMessageList(), context);
                }
            } while (receivedBytes.length != 0 && shouldContinue);

        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }

        return result;
    }

    /**
     * TODO FIX CODE DUPLICATION
     */
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
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }
        return result;
    }

    public MessageActionResult handleReceivedBytes(byte[] receivedBytes, TlsContext context) {
        MessageActionResult result = new MessageActionResult();
        if (receivedBytes.length > 0) {
            List<AbstractRecord> tempRecords = parseRecords(receivedBytes, context);
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                orderDtlsRecords(tempRecords);
            }
            List<RecordGroup> recordGroups = RecordGroup.generateRecordGroups(tempRecords);
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
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving messages.", ex);
            context.setReceivedTransportHandlerException(true);
        }
        return realRecords;
    }

    private boolean testIfReceivedFatalAlert(List<ProtocolMessage> messages) {
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

    private boolean testIfReceivedAllExpectedMessage(List<ProtocolMessage> expectedMessages,
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

    private boolean testIfWeShouldContinueToReceive(List<ProtocolMessage> expectedMessages,
        List<ProtocolMessage> receivedMessages, TlsContext context) {

        boolean receivedFatalAlert = testIfReceivedFatalAlert(receivedMessages);
        if (receivedFatalAlert) {
            return false;
        }
        boolean receivedAllExpectedMessages =
            testIfReceivedAllExpectedMessage(expectedMessages, receivedMessages, context.getConfig().isEarlyStop());
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            return !receivedAllExpectedMessages || !context.getDtlsFragmentManager().areAllMessageFragmentsComplete();
        } else {
            return !receivedAllExpectedMessages;
        }
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

    private boolean isListOnlyDtlsHandshakeMessageFragments(List<ProtocolMessage> messages) {
        for (ProtocolMessage message : messages) {
            if (!(message instanceof DtlsHandshakeMessageFragment)) {
                return false;
            }
        }
        return true;
    }

    public MessageParsingResult parseMessages(RecordGroup recordGroup, TlsContext context) {
        // Due to TLS 1.3 Encrypted Type it might be necessary to look for
        // new groups here
        List<ProtocolMessage> messages = new LinkedList<>();
        List<DtlsHandshakeMessageFragment> messageFragments = null;
        for (RecordGroup group : RecordGroup.generateRecordGroups(recordGroup.getRecords())) {

            List<RecordGroup> subGroups = group.splitIntoProcessableSubgroups();
            for (RecordGroup subGroup : subGroups) {

                byte[] cleanProtocolMessageBytes;
                if (context.getChooser().getSelectedProtocolVersion().isDTLS()
                    && subGroup.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
                    List<ProtocolMessage> messageList =
                        handleDtlsHandshakeRecordBytes(subGroup.getCleanBytes(), context, true, subGroup.getDtlsEpoch());
                    if (isListOnlyDtlsHandshakeMessageFragments(messageList)) {
                        messageFragments = convertToDtlsFragmentList(messageList);
                        List<DtlsHandshakeMessageFragment> defragmentedRecordedFragments =
                            defragmentAndReorder(messageFragments, context);
                        for (DtlsHandshakeMessageFragment fragment : defragmentedRecordedFragments) {
                            context.setDtlsReadHandshakeMessageSequence(fragment.getMessageSeq().getValue());
                            List<ProtocolMessage> parsedMessages =
                                handleCleanBytes(convertDtlsFragmentToCleanTlsBytes(fragment),
                                    subGroup.getProtocolMessageType(), context, false, subGroup.areAllRecordsValid()
                                        || context.getConfig().getParseInvalidRecordNormally());
                            messages.addAll(parsedMessages);
                        }
                    } else {
                        LOGGER
                            .warn("Receive non DTLS-Handshake message Fragment - Not trying to defragment this - passing as is (probably wrong)");
                        cleanProtocolMessageBytes = subGroup.getCleanBytes();
                        List<ProtocolMessage> parsedMessages =
                            handleCleanBytes(cleanProtocolMessageBytes, subGroup.getProtocolMessageType(), context,
                                false, subGroup.areAllRecordsValid()
                                    || context.getConfig().getParseInvalidRecordNormally());
                        messages.addAll(parsedMessages);
                    }

                } else {
                    cleanProtocolMessageBytes = subGroup.getCleanBytes();
                    List<ProtocolMessage> parsedMessages =
                        handleCleanBytes(cleanProtocolMessageBytes, subGroup.getProtocolMessageType(), context, false,
                            subGroup.areAllRecordsValid() || context.getConfig().getParseInvalidRecordNormally());
                    messages.addAll(parsedMessages);
                }
            }
        }
        return new MessageParsingResult(messages, messageFragments);
    }

    /**
     * Takes a list of AbstractRecords and tries to sort them by their
     * epoch/sqn. The sorting ist epoch > sqn. Smaller epochs are sorted before
     * bigger epochs smaller sqns are sorted before higher sqns
     *
     * @param abstractRecordList
     * List that should be sorted
     * @throws UnsortableRecordsExceptions
     * If the list contains blob records
     */
    private void orderDtlsRecords(List<AbstractRecord> abstractRecordList) throws UnsortableRecordsExceptions {
        for (AbstractRecord abstractRecord : abstractRecordList) {
            if (abstractRecord instanceof BlobRecord) {
                throw new UnsortableRecordsExceptions("RecordList contains BlobRecords. Cannot sort by SQN/EPOCH");
            }
        }
        abstractRecordList.sort(new Comparator<AbstractRecord>() {
            @Override
            public int compare(AbstractRecord o1, AbstractRecord o2) {
                Record r1 = (Record) o1;
                Record r2 = (Record) o2;
                if (r1.getEpoch().getValue() > r2.getEpoch().getValue()) {
                    return 1;
                } else if (r1.getEpoch().getValue() < r2.getEpoch().getValue()) {
                    return -1;
                } else {
                    return r1.getSequenceNumber().getValue().compareTo(r2.getSequenceNumber().getValue());
                }
            }
        });

    }

    /**
     * Tries to parse a byte array as DTLS handshake message fragments, if this
     * does not work they are parsed as unknown messages
     *
     * @param recordBytes
     * @param context
     * @param onlyParse
     * @return
     */
    private List<ProtocolMessage> handleDtlsHandshakeRecordBytes(byte[] recordBytes, TlsContext context,
        boolean onlyParse, int dtlsEpoch) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedFragments = new LinkedList<>();

        while (dataPointer < recordBytes.length) {
            ParserResult result = null;
            try {
                result = tryHandleAsDtlsHandshakeMessageFragments(recordBytes, dataPointer, context);
            } catch (ParserException | AdjustmentException | UnsupportedOperationException exCorrectMsg) {
                LOGGER.warn("Could not parse Message as DtlsHandshakeMessageFragment");
                LOGGER.debug(exCorrectMsg);
                try {
                    result = tryHandleAsUnknownMessage(recordBytes, dataPointer, context);
                } catch (ParserException | AdjustmentException | UnsupportedOperationException exUnknownHMsg) {
                    LOGGER.warn("Could not parse Message as UnknownMessage");
                    LOGGER.debug(exUnknownHMsg);
                    break;
                }
            }
            if (result != null) {
                if (dataPointer == result.getParserPosition()) {
                    throw new ParserException("Ran into an infinite loop while parsing ProtocolMessages");
                }
                dataPointer = result.getParserPosition();
                LOGGER.debug("The following message was parsed: {}", result.getMessage().toString());
                if (result.getMessage() instanceof DtlsHandshakeMessageFragment) {
                    ((DtlsHandshakeMessageFragment) result.getMessage()).setEpoch(dtlsEpoch);
                }
                receivedFragments.add(result.getMessage());
            }
        }
        return receivedFragments;
    }

    private List<ProtocolMessage> handleCleanBytes(byte[] cleanProtocolMessageBytes,
        ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse, boolean tryParseAsValid) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        while (dataPointer < cleanProtocolMessageBytes.length) {
            ParserResult result = null;
            if (tryParseAsValid) {
                try {
                    if (typeFromRecord != null) {
                        if (typeFromRecord == ProtocolMessageType.APPLICATION_DATA
                            && context.getConfig().isHttpsParsingEnabled()) {
                            try {
                                result = tryHandleAsHttpsMessage(cleanProtocolMessageBytes, dataPointer, context);
                            } catch (ParserException | AdjustmentException | UnsupportedOperationException e) {
                                result =
                                    tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                        context, onlyParse);
                            }
                        } else {
                            result =
                                tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                    context, onlyParse);
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
                            result =
                                tryHandleAsUnknownHandshakeMessage(cleanProtocolMessageBytes, dataPointer,
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
            } else {
                try {
                    result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context);
                } catch (ParserException | AdjustmentException | UnsupportedOperationException exUnknownHMsg) {
                    LOGGER.warn("Could not parse Message as UnknownMessage");
                    LOGGER.debug(exUnknownHMsg);
                    break;
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
        ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse) throws ParserException,
        AdjustmentException {

        if (typeFromRecord == ProtocolMessageType.UNKNOWN) {
            return tryHandleAsSslMessage(protocolMessageBytes, pointer, context);
        } else {
            HandshakeMessageType handshakeMessageType =
                HandshakeMessageType.getMessageType(protocolMessageBytes[pointer]);
            ProtocolMessageHandler protocolMessageHandler =
                HandlerFactory.getHandler(context, typeFromRecord, handshakeMessageType);
            return protocolMessageHandler.parseMessage(protocolMessageBytes, pointer, onlyParse);
        }
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

    public ParserResult tryHandleAsDtlsHandshakeMessageFragments(byte[] recordBytes, int pointer, TlsContext context)
        throws ParserException, AdjustmentException {
        DtlsHandshakeMessageFragmentHandler dtlsHandshakeMessageHandler =
            new DtlsHandshakeMessageFragmentHandler(context);
        return dtlsHandshakeMessageHandler.parseMessage(recordBytes, pointer, false);
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

    private List<DtlsHandshakeMessageFragment> defragmentAndReorder(List<DtlsHandshakeMessageFragment> fragments,
        TlsContext context) {

        FragmentManager fragmentManager = context.getDtlsFragmentManager();
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            fragmentManager.addMessageFragment(fragment);
        }
        List<DtlsHandshakeMessageFragment> orderedCombinedUninterpretedMessageFragments =
            fragmentManager.getOrderedCombinedUninterpretedMessageFragments(true);
        return orderedCombinedUninterpretedMessageFragments;

    }

    /*
     * Processes a fragmented message by extracting the underlying message.
     */
    private byte[] convertDtlsFragmentToCleanTlsBytes(DtlsHandshakeMessageFragment fragment) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(fragment.getType().getValue());
        try {
            stream.write(ArrayConverter.intToBytes(fragment.getLength().getValue(),
                HandshakeByteLength.MESSAGE_LENGTH_FIELD));
            stream.write(fragment.getContent().getValue());
        } catch (IOException ex) {
            LOGGER.warn("Could not write fragment to stream.", ex);
        }
        return stream.toByteArray();
    }

    private List<DtlsHandshakeMessageFragment> convertToDtlsFragmentList(List<ProtocolMessage> messageList) {
        List<DtlsHandshakeMessageFragment> fragmentList = new LinkedList<>();
        for (ProtocolMessage message : messageList) {
            fragmentList.add((DtlsHandshakeMessageFragment) message);
        }
        return fragmentList;
    }
}
