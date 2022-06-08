/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.dtls.FragmentManager;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.UnsortableRecordsExceptions;
import de.rub.nds.tlsattacker.core.https.HttpsRequestHandler;
import de.rub.nds.tlsattacker.core.https.HttpsResponseHandler;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.handler.*;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.ParserResult;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean failedToReceiveMoreRecords = false;

    public ReceiveMessageHelper() {
    }

    public MessageActionResult receiveMessages(TlsContext context) {
        return receiveMessages(new LinkedList<>(), context);
    }

    /**
     * Receives messages, and tries to receive the messages specified in messages
     *
     * @param  expectedMessages
     *                          Messages which should be received
     * @param  context
     *                          The context on which Messages should be received
     * @return                  Actually received Messages
     */
    public MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages, TlsContext context) {
        context.setTalkingConnectionEndType(context.getChooser().getMyConnectionPeer());
        MessageActionResult result = new MessageActionResult();

        try {
            byte[] receivedBytes;
            int receivedBytesLength = 0;
            boolean shouldContinue = true;
            do {
                receivedBytes = receiveByteArray(context);
                receivedBytesLength += receivedBytes.length;

                result.merge(handleReceivedBytes(receivedBytes, context));
                if (context.getConfig().isQuickReceive() && !expectedMessages.isEmpty()) {
                    shouldContinue =
                        testIfWeShouldContinueToReceive(expectedMessages, result.getMessageList(), context);
                }
                if (receivedBytesLength >= context.getConfig().getReceiveMaximumBytes()) {
                    shouldContinue = false;
                }
            } while (receivedBytes.length != 0 && shouldContinue);

        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving for Messages.");
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
            int receivedBytesLength = 0;
            boolean shouldContinue = true;
            do {
                receivedBytes = receiveByteArray(context);
                receivedBytesLength += receivedBytes.length;

                result.merge(handleReceivedBytes(receivedBytes, context));
                boolean receivedFatalAlert = testIfReceivedFatalAlert(result.getMessageList());
                if (receivedFatalAlert && context.getConfig().isStopReceivingAfterFatal()) {
                    break;
                }
                boolean receivedWarningAlert = testIfReceivedWarningAlert(result.getMessageList());
                if (receivedWarningAlert && context.getConfig().getStopReceivingAfterWarning()) {
                    break;
                }

                for (ProtocolMessage message : result.getMessageList()) {
                    if (message.getClass().equals(waitTillMessage.getClass())) {
                        LOGGER.debug("Received message we waited for");
                        shouldContinue = false;
                        break;
                    }
                }
                if (context.getChooser().getSelectedProtocolVersion().isDTLS() && shouldContinue == false) {
                    for (int i = 0; i <= context.getDtlsReadHandshakeMessageSequence(); i++) {
                        if (!context.getDtlsReceivedHandshakeMessageSequences().contains(i)) {
                            shouldContinue = true;
                            break;
                        }
                    }
                }
                if (receivedBytesLength >= context.getConfig().getReceiveMaximumBytes()) {
                    shouldContinue = false;
                }
            } while (receivedBytes.length != 0 && shouldContinue);
        } catch (IOException ex) {
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving for Messages.");
            LOGGER.debug(ex);
            context.setReceivedTransportHandlerException(true);
        }
        return result;
    }

    public MessageActionResult handleReceivedBytes(byte[] receivedBytes, TlsContext context) {
        MessageActionResult result = new MessageActionResult();
        failedToReceiveMoreRecords = false;
        byte[] preservedDigest = context.getDigest().getRawBytes();
        if (receivedBytes.length > 0) {
            List<AbstractRecord> tempRecords = parseRecords(receivedBytes, context);
            result = processUngroupedRecords(tempRecords, context);
        }

        return result;
    }

    private MessageActionResult processUngroupedRecords(List<AbstractRecord> tempRecords, TlsContext context) {
        MessageActionResult result = new MessageActionResult();
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            orderDtlsRecords(tempRecords);
        }
        List<RecordGroup> recordGroups = RecordGroup.generateRecordGroups(tempRecords);
        for (int groupIndex = 0; groupIndex < recordGroups.size(); groupIndex++) {
            RecordGroup currentGroup = recordGroups.get(groupIndex);

            boolean foundValidRecordInGroup = false;
            byte[] preservedDigest = context.getDigest().getRawBytes();
            CipherState state = context.getRecordLayer().getDecryptor().getRecordMostRecentCipher().getState();
            long preservedReadSQN = state.getReadSequenceNumber();

            for (int recordIndex = 0; recordIndex < recordGroups.get(groupIndex).getRecords().size(); recordIndex++) {
                currentGroup.decryptRecord(context, recordIndex);
                currentGroup.checkRecordDataSize(context, recordIndex);
                currentGroup.adjustContextForRecord(context, recordIndex);

                if (currentGroup.areAllRecordsValid()) {
                    foundValidRecordInGroup = true;
                } else if (!currentGroup.areAllRecordsValid() && foundValidRecordInGroup) {
                    state.setReadSequenceNumber(state.getReadSequenceNumber() - 1);
                    formNewGroupFromLastAndComingRecords(recordIndex, groupIndex, recordGroups);
                }
            }

            try {
                result.merge(parseRecordGroup(recordGroups.get(groupIndex), context));
            } catch (ParserException parserException) {
                List<AbstractRecord> additionalRecords = tryToFetchAdditionalRecords(context);
                RecordGroup.mergeRecordsIntoGroups(recordGroups, additionalRecords);
                restorePreGroupState(context, preservedDigest, preservedReadSQN);
                groupIndex--;
            }
        }
        return result;
    }

    private void restorePreGroupState(TlsContext context, byte[] preservedDigest, long preservedReadSQN) {
        context.getDigest().setRawBytes(preservedDigest);
        context.getRecordLayer().getDecryptor().getRecordMostRecentCipher().getState()
            .setReadSequenceNumber(preservedReadSQN);
    }

    private List<AbstractRecord> tryToFetchAdditionalRecords(TlsContext context) {
        LOGGER.debug("Encountered ParserException while processing Records - will attempt to receive further Records");
        byte[] additionalBytes = tryToFetchAdditionalBytes(context);
        if (additionalBytes != null && additionalBytes.length > 0) {
            List<AbstractRecord> fetchedRecords = parseRecords(additionalBytes, context);
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                orderDtlsRecords(fetchedRecords);
            }
            return fetchedRecords;
        } else {
            LOGGER.warn("Could not receive more Records after ParserException - Parsing will fail");
            failedToReceiveMoreRecords = true;
            return new LinkedList<>();
        }
    }

    /**
     * Records (in TLS 1.3) might have been protected using different keys they need to be decrypted and processed
     * sequentially.
     */
    private void formNewGroupFromLastAndComingRecords(int recordIndex, int groupIndex, List<RecordGroup> recordGroups) {
        LOGGER
            .debug("Found invalid Record after valid ones - will parse other messages first and reattempt decryption");
        List<AbstractRecord> recordsForGroup = new LinkedList<>();
        for (int i = recordIndex; i < recordGroups.get(groupIndex).getRecords().size(); i++) {
            recordsForGroup.add(recordGroups.get(groupIndex).getRecords().get(i));
        }

        // Records were in one group before, they thus will remain in one group
        RecordGroup createdGroup = RecordGroup.generateRecordGroups(recordsForGroup).get(0);
        recordGroups.get(groupIndex).removeFromGroup(createdGroup.getRecords());
        recordGroups.add(groupIndex + 1, createdGroup);
    }

    private MessageActionResult parseRecordGroup(RecordGroup recordGroup, TlsContext context) {
        MessageParsingResult messageParsingResult = parseMessages(recordGroup, context);

        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (recordGroupIndicatesWrongTls13KeySet(messageParsingResult.getMessages(), recordGroup)) {
                LOGGER.warn(
                    "Messages obtained from RecordGroup indicate that peer's keys have not been updated properly");
                context.setReceivedMessageWithWrongTls13KeyType(true);
            }
        }

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
            LOGGER.warn("Received " + ex.getLocalizedMessage() + " while receiving for Messages.", ex);
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

    private boolean testIfReceivedWarningAlert(List<ProtocolMessage> messages) {
        for (ProtocolMessage message : messages) {
            if (message instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) message;
                if (alert.getLevel().getValue() == AlertLevel.WARNING.getValue()) {
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
                    return earlyStop;
                }
            }
        }
        return true;
    }

    private boolean testIfWeShouldContinueToReceive(List<ProtocolMessage> expectedMessages,
        List<ProtocolMessage> receivedMessages, TlsContext context) {

        boolean receivedFatalAlert = testIfReceivedFatalAlert(receivedMessages);
        if (receivedFatalAlert && context.getConfig().isStopReceivingAfterFatal()) {
            return false;
        }
        boolean receivedWarningAlert = testIfReceivedWarningAlert(receivedMessages);
        if (receivedWarningAlert && context.getConfig().getStopReceivingAfterWarning()) {
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
        return context.getTransportHandler().fetchData();
    }

    private List<AbstractRecord> parseRecords(byte[] recordBytes, TlsContext context) {
        try {
            return context.getRecordLayer().parseRecords(recordBytes);
        } catch (ParserException ex) {
            LOGGER.debug(ex);
            if (context.getTransportHandler() != null) {
                LOGGER.debug("Could not parse provided Bytes into records. Waiting for more Packets");
                byte[] extraBytes = tryToFetchAdditionalBytes(context);
                if (extraBytes != null && extraBytes.length > 0) {
                    return parseRecords(ArrayConverter.concatenate(recordBytes, extraBytes), context);
                }
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
                    List<ProtocolMessage> messageList = handleDtlsHandshakeRecordBytes(subGroup.getCleanBytes(),
                        context, true, subGroup.getDtlsEpoch());
                    if (isListOnlyDtlsHandshakeMessageFragments(messageList)) {
                        messageFragments = convertToDtlsFragmentList(messageList);
                        List<DtlsHandshakeMessageFragment> defragmentedReorderedFragments =
                            defragmentAndReorder(messageFragments, context);
                        for (DtlsHandshakeMessageFragment fragment : defragmentedReorderedFragments) {
                            context.setDtlsReadHandshakeMessageSequence(fragment.getMessageSeq().getValue());
                            context.addDtlsReceivedHandshakeMessageSequences(fragment.getMessageSeq().getValue());
                            List<ProtocolMessage> parsedMessages = handleCleanBytes(
                                convertDtlsFragmentToCleanTlsBytes(fragment), subGroup.getProtocolMessageType(),
                                context, fragment.isRetransmission(),
                                subGroup.areAllRecordsValid() || context.getConfig().getParseInvalidRecordNormally());
                            ((HandshakeMessage) parsedMessages.get(0)).setRetransmission(fragment.isRetransmission());
                            ((HandshakeMessage) parsedMessages.get(0))
                                .setIncludeInDigest(fragment.getIncludeInDigest());
                            messages.addAll(parsedMessages);
                        }
                    } else {
                        LOGGER.warn(
                            "Receive non DTLS-Handshake message Fragment - Not trying to defragment this - passing as is (probably wrong)");
                        cleanProtocolMessageBytes = subGroup.getCleanBytes();
                        List<ProtocolMessage> parsedMessages = handleCleanBytes(cleanProtocolMessageBytes,
                            subGroup.getProtocolMessageType(), context, false,
                            subGroup.areAllRecordsValid() || context.getConfig().getParseInvalidRecordNormally());
                        messages.addAll(parsedMessages);
                    }

                } else if (context.getChooser().getSelectedProtocolVersion().isDTLS()
                    && subGroup.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                    for (AbstractRecord record : subGroup.getRecords()) {
                        boolean added = context.addDtlsReceivedChangeCipherSpecEpochs(subGroup.getDtlsEpoch());
                        if (!added && context.getConfig().isIgnoreRetransmittedCcsInDtls()) {
                            continue;
                        }
                        cleanProtocolMessageBytes = record.getCleanProtocolMessageBytes().getValue();
                        List<ProtocolMessage> parsedMessages = handleCleanBytes(cleanProtocolMessageBytes,
                            subGroup.getProtocolMessageType(), context, false,
                            subGroup.areAllRecordsValid() || context.getConfig().getParseInvalidRecordNormally());
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
     * Takes a list of AbstractRecords and tries to sort them by their epoch/sqn. The sorting ist epoch > sqn. Smaller
     * epochs are sorted before bigger epochs smaller sqns are sorted before higher sqns
     *
     * @param  abstractRecordList
     *                                     List that should be sorted
     * @throws UnsortableRecordsExceptions
     *                                     If the list contains blob records
     */
    private void orderDtlsRecords(List<AbstractRecord> abstractRecordList) throws UnsortableRecordsExceptions {

        abstractRecordList.sort(new Comparator<AbstractRecord>() {
            @Override
            public int compare(AbstractRecord o1, AbstractRecord o2) {
                if (o1 instanceof Record && o2 instanceof Record) {
                    Record r1 = (Record) o1;
                    Record r2 = (Record) o2;
                    if (r1.getEpoch().getValue() > r2.getEpoch().getValue()) {
                        return 1;
                    } else if (r1.getEpoch().getValue() < r2.getEpoch().getValue()) {
                        return -1;
                    } else {
                        return r1.getSequenceNumber().getValue().compareTo(r2.getSequenceNumber().getValue());
                    }
                } else {
                    // Ok we are now sorting blob records....
                    if (o1 instanceof Record) {
                        return 1;
                    } else if (o2 instanceof Record) {
                        return -1;
                    } else {
                        byte[] a = o1.getCompleteRecordBytes().getValue();
                        byte[] b = o2.getCompleteRecordBytes().getValue();
                        if (a == b) { // also covers the case of two null arrays. those are considered 'equal'
                            return 0;
                        }

                        // arbitrary: non-null array is considered 'greater than' null array
                        if (a == null) {
                            return -1; // "a < b"
                        } else if (b == null) {
                            return 1; // "a > b"
                        }

                        // now the item-by-item comparison - the loop runs as long as items in both arrays are equal
                        int last = Math.min(a.length, b.length);
                        for (int i = 0; i < last; i++) {
                            Byte ai = a[i];
                            Byte bi = b[i];

                            if (ai == null && bi == null) {
                                continue; // two null items are assumed 'equal'
                            } else if (ai == null) { // arbitrary: non-null item is considered 'greater than' null item
                                return -1; // "a < b"
                            } else if (bi == null) {
                                return 1; // "a > b"
                            }

                            int comp = ai.compareTo(bi);
                            if (comp != 0) {
                                return comp;
                            }
                        }

                        // shorter array whose items are all equal to the first items of a longer array is considered
                        // 'less than'
                        if (a.length < b.length) {
                            return -1; // "a < b"
                        } else if (a.length > b.length) {
                            return 1; // "a > b"
                        }

                        // i.e. (a.length == b.length)
                        return 0; // "a = b", same length, all items equal
                    }

                }
            }
        });

    }

    /**
     * Tries to parse a byte array as DTLS handshake message fragments, if this does not work they are parsed as unknown
     * messages
     *
     * @param  recordBytes
     * @param  context
     * @param  onlyParse
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
                    result =
                        tryHandleAsUnknownMessage(recordBytes, dataPointer, context, ProtocolMessageType.HANDSHAKE);
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

    private List<ProtocolMessage> handleCleanBytes(byte[] cleanProtocolMessageBytes, ProtocolMessageType typeFromRecord,
        TlsContext context, boolean onlyParse, boolean tryParseAsValid) {
        int dataPointer = 0;
        List<ProtocolMessage> receivedMessages = new LinkedList<>();
        /*
         * empty application data message
         */
        if (cleanProtocolMessageBytes.length == 0 && typeFromRecord == ProtocolMessageType.APPLICATION_DATA) {
            receivedMessages.add(new ApplicationMessage());
        }
        ParserResult result = null;
        while (dataPointer < cleanProtocolMessageBytes.length) {
            if (tryParseAsValid) {
                try {
                    if (typeFromRecord != null) {
                        if (typeFromRecord == ProtocolMessageType.APPLICATION_DATA
                            && context.getConfig().isHttpsParsingEnabled()) {
                            try {
                                result = tryHandleAsHttpsMessage(cleanProtocolMessageBytes, dataPointer, context);
                            } catch (ParserException | AdjustmentException | UnsupportedOperationException e) {
                                result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer,
                                    typeFromRecord, context, onlyParse);
                            }
                        } else {
                            result = tryHandleAsCorrectMessage(cleanProtocolMessageBytes, dataPointer, typeFromRecord,
                                context, onlyParse);
                        }
                    } else {
                        if (cleanProtocolMessageBytes.length > 2) {
                            result = tryHandleAsSslMessage(cleanProtocolMessageBytes, dataPointer, context);
                        } else {
                            result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context,
                                typeFromRecord);
                        }
                    }
                } catch (ParserException | AdjustmentException | UnsupportedOperationException exCorrectMsg) {
                    if (exCorrectMsg instanceof ParserException && !failedToReceiveMoreRecords) {
                        throw new ParserException(exCorrectMsg);
                    }
                    LOGGER.warn("Could not parse Message as a CorrectMessage");
                    LOGGER.debug(exCorrectMsg);
                    try {
                        if (typeFromRecord == ProtocolMessageType.HANDSHAKE) {
                            LOGGER.warn("Trying to parse Message as UnknownHandshakeMessage");
                            result = tryHandleAsUnknownHandshakeMessage(cleanProtocolMessageBytes, dataPointer,
                                typeFromRecord, context);
                        } else {
                            try {
                                result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context,
                                    typeFromRecord);
                            } catch (ParserException | AdjustmentException
                                | UnsupportedOperationException exUnknownHMsg) {
                                LOGGER.warn("Could not parse Message as UnknownMessage");
                                LOGGER.debug(exUnknownHMsg);
                                break;
                            }
                        }
                    } catch (ParserException | UnsupportedOperationException exUnknownHandshakeMsg) {
                        LOGGER.warn("Could not parse Message as UnknownHandshakeMessage");
                        LOGGER.debug(exUnknownHandshakeMsg);

                        try {
                            result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context,
                                typeFromRecord);
                        } catch (ParserException | AdjustmentException | UnsupportedOperationException exUnknownHMsg) {
                            LOGGER.warn("Could not parse Message as UnknownMessage");
                            LOGGER.debug(exUnknownHMsg);
                            break;
                        }
                    }
                }
            } else {
                try {
                    result = tryHandleAsUnknownMessage(cleanProtocolMessageBytes, dataPointer, context, typeFromRecord);
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
                result = null;
            }
        }
        if (result != null) {
            receivedMessages.add(result.getMessage());
        }
        return receivedMessages;
    }

    private ParserResult tryHandleAsHttpsMessage(byte[] protocolMessageBytes, int pointer, TlsContext context)
        throws ParserException, AdjustmentException {
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            HttpsRequestHandler handler = new HttpsRequestHandler(context);
            return parseMessage(handler, protocolMessageBytes, pointer, false, context);
        } else {
            HttpsResponseHandler handler = new HttpsResponseHandler(context);
            return parseMessage(handler, protocolMessageBytes, pointer, false, context);
        }
    }

    private ParserResult tryHandleAsCorrectMessage(byte[] protocolMessageBytes, int pointer,
        ProtocolMessageType typeFromRecord, TlsContext context, boolean onlyParse)
        throws ParserException, AdjustmentException {

        if (typeFromRecord == ProtocolMessageType.UNKNOWN) {
            return tryHandleAsSslMessage(protocolMessageBytes, pointer, context);
        } else {
            HandshakeMessageType handshakeMessageType =
                HandshakeMessageType.getMessageType(protocolMessageBytes[pointer]);
            ProtocolMessageHandler protocolMessageHandler =
                HandlerFactory.getHandler(context, typeFromRecord, handshakeMessageType);
            return parseMessage(protocolMessageHandler, protocolMessageBytes, pointer, onlyParse, context);
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

        if (cleanProtocolMessageBytes.length > (dataPointer + typeOffset)
            && cleanProtocolMessageBytes[dataPointer + typeOffset]
                == HandshakeMessageType.SSL2_SERVER_HELLO.getValue()) {
            handler = new SSL2ServerHelloHandler(context);
        } else {
            // The SSL2ServerVerifyMessage is currently not supported for parsing purposes
            // handler = new SSL2ServerVerifyHandler(context);
            throw new ParserException("SSL2ServerVerifyMessage is not supported");
        }
        return parseMessage(handler, cleanProtocolMessageBytes, dataPointer, false, context);
    }

    public ParserResult tryHandleAsDtlsHandshakeMessageFragments(byte[] recordBytes, int pointer, TlsContext context)
        throws ParserException, AdjustmentException {
        DtlsHandshakeMessageFragmentHandler dtlsHandshakeMessageHandler =
            new DtlsHandshakeMessageFragmentHandler(context);
        return parseMessage(dtlsHandshakeMessageHandler, recordBytes, pointer, false, context);
    }

    private ParserResult tryHandleAsUnknownHandshakeMessage(byte[] protocolMessageBytes, int pointer,
        ProtocolMessageType typeFromRecord, TlsContext context) throws ParserException, AdjustmentException {
        ProtocolMessageHandler pmh = HandlerFactory.getHandler(context, typeFromRecord, HandshakeMessageType.UNKNOWN);
        return parseMessage(pmh, protocolMessageBytes, pointer, false, context);
    }

    private ParserResult tryHandleAsUnknownMessage(byte[] protocolMessageBytes, int pointer, TlsContext context,
        ProtocolMessageType recordContentMessageType) throws ParserException, AdjustmentException {
        UnknownMessageHandler unknownHandler = new UnknownMessageHandler(context, recordContentMessageType);
        return parseMessage(unknownHandler, protocolMessageBytes, pointer, false, context);
    }

    private List<DtlsHandshakeMessageFragment> defragmentAndReorder(List<DtlsHandshakeMessageFragment> fragments,
        TlsContext context) {

        FragmentManager fragmentManager = context.getDtlsFragmentManager();
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            fragmentManager.addMessageFragment(fragment);
        }
        List<DtlsHandshakeMessageFragment> orderedCombinedUninterpretedMessageFragments =
            fragmentManager.getOrderedCombinedUninterpretedMessageFragments(true, false);
        return orderedCombinedUninterpretedMessageFragments;

    }

    /*
     * Processes a fragmented message by extracting the underlying message.
     */
    private byte[] convertDtlsFragmentToCleanTlsBytes(DtlsHandshakeMessageFragment fragment) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(fragment.getType().getValue());
        try {
            stream.write(
                ArrayConverter.intToBytes(fragment.getLength().getValue(), HandshakeByteLength.MESSAGE_LENGTH_FIELD));
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

    /**
     * Parses a byteArray from a Position into a MessageObject and returns the parsed MessageObjet and parser position
     * in a parser result. The current Chooser is adjusted as
     *
     * @param  message
     *                 The byte[] messages which should be parsed
     * @param  pointer
     *                 The pointer (startposition) into the message bytes
     * @param  context
     * @return         The Parser result
     */
    public <T extends ProtocolMessage> ParserResult parseMessage(ProtocolMessageHandler<T> handler, byte[] message,
        int pointer, boolean onlyParse, TlsContext context) {
        ProtocolMessageParser<T> parser = handler.getParser(message, pointer);
        T parsedMessage = parser.parse();

        if (context.getChooser().getSelectedProtocolVersion().isDTLS() && parsedMessage instanceof HandshakeMessage
            && !(parsedMessage instanceof DtlsHandshakeMessageFragment)) {
            ((HandshakeMessage) parsedMessage).setMessageSequence(context.getDtlsReadHandshakeMessageSequence());
        }
        try {
            if (!onlyParse) {
                handler.prepareAfterParse(parsedMessage);
                handler.getPreparator(parsedMessage).prepareAfterParse(context.isReversePrepareAfterParse());

                if (handler instanceof TlsMessageHandler) {
                    ((TlsMessageHandler) handler).updateDigest(parsedMessage);
                }

                handler.adjustContext(parsedMessage);
            }

        } catch (AdjustmentException | UnsupportedOperationException e) {
            LOGGER.warn("Could not adjust TLSContext");
            LOGGER.debug(e);
        }
        return new ParserResult(parsedMessage, parser.getPointer());
    }

    private byte[] tryToFetchAdditionalBytes(TlsContext context) {
        try {
            return receiveByteArray(context);
        } catch (IOException ex2) {
            LOGGER.warn("Could not receive more Bytes", ex2);
            context.setReceivedTransportHandlerException(true);
        }

        return new byte[0];
    }

    /**
     * Due to the way we handle records, we accept messages that have been encrypted using an old key type as long as
     * the message that initiates a key change has been received together with the new one - messages for which we
     * expect different key types must never appear in one record group
     */
    private boolean recordGroupIndicatesWrongTls13KeySet(List<ProtocolMessage> parsedMessages,
        RecordGroup recordGroup) {
        Set<Tls13KeySetType> expectedKeyTypes = new HashSet<>();
        for (ProtocolMessage msg : parsedMessages) {
            if (!(msg instanceof TlsMessage)) {
                continue;
            }

            switch (((TlsMessage) msg).getProtocolMessageType()) {
                case HANDSHAKE:
                    if (msg instanceof NewSessionTicketMessage || msg instanceof KeyUpdateMessage) {
                        expectedKeyTypes.add(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                    } else if (msg instanceof ClientHelloMessage || msg instanceof ServerHelloMessage) {
                        expectedKeyTypes.add(Tls13KeySetType.NONE);
                    } else {
                        expectedKeyTypes.add(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
                    }
                    break;
                case APPLICATION_DATA:
                    expectedKeyTypes.add(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                    break;
                default:
                    // ALERT may have different KeyTypes (see RC8446 A.1. Client)
                    // Other types are legacy or due to parsing error
            }
        }

        if (expectedKeyTypes.size() > 1) {
            return true;
        } else if (expectedKeyTypes.size() == 1) {
            for (AbstractRecord abstractRecord : recordGroup.getRecords()) {
                if (abstractRecord instanceof Record) {
                    expectedKeyTypes.remove(((Record) abstractRecord).getComputations().getUsedTls13KeySetType());
                }
            }
            return !expectedKeyTypes.isEmpty();
        }
        return false;
    }
}
