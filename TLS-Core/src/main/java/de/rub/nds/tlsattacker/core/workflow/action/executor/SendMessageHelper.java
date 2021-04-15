/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.dtls.MessageFragmenter;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendMessageHelper() {
    }

    public MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records,
        TlsContext context) throws IOException {
        return sendMessages(messages, records, context, true);
    }

    public MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records,
        TlsContext context, boolean prepareMessages) throws IOException {
        List<DtlsHandshakeMessageFragment> fragmentMessages = new LinkedList<>();
        context.setTalkingConnectionEndType(context.getChooser().getConnectionEndType());
        if (records == null) {
            LOGGER.trace("No Records Specified, creating emtpy list");
            records = new LinkedList<>();
        }

        int recordPosition = 0;
        ProtocolMessageType lastType = null;
        ProtocolMessage lastMessage = null;
        MessageBytesCollector messageBytesCollector = new MessageBytesCollector();
        MessageFragmenter fragmenter = new MessageFragmenter(context.getConfig().getDtlsMaximumFragmentLength());
        List<AbstractRecord> preservedRecords = new LinkedList<>();
        if (context.getConfig().isPreserveMessageRecordRelation()) {
            preservedRecords = records;
            records = new LinkedList<>();
        }
        for (int i = 0; i < messages.size(); i++) {
            ProtocolMessage protocolMessage = messages.get(i);

            if (protocolMessage instanceof TlsMessage) {
                TlsMessage tlsMessage = (TlsMessage) protocolMessage;

                if (context.getConfig().isPreserveMessageRecordRelation() && i < preservedRecords.size()) {
                    records.add(preservedRecords.get(i));
                }
                if (tlsMessage.getProtocolMessageType() != lastType && lastMessage != null
                    && context.getConfig().isFlushOnMessageTypeChange()) {
                    recordPosition =
                        flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
                    if (lastMessage.getAdjustContext() && lastMessage instanceof TlsMessage) {
                        TlsMessageHandler<TlsMessage> tlsMessageHandler = lastMessage.getHandler(context);
                        tlsMessageHandler.adjustTlsContextAfterSerialize((TlsMessage) lastMessage);
                    }
                    lastMessage = null;
                }
                lastMessage = tlsMessage;
                lastType = tlsMessage.getProtocolMessageType();
                if (prepareMessages) {
                    LOGGER.debug("Preparing " + tlsMessage.toCompactString());
                }
            }

            byte[] protocolMessageBytes = prepareMessage(protocolMessage, prepareMessages, context);
            if (protocolMessage.isGoingToBeSent()) {
                if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                    if (protocolMessage instanceof HandshakeMessage) {
                        HandshakeMessage handshakeMessage = (HandshakeMessage) protocolMessage;
                        List<DtlsHandshakeMessageFragment> messageFragments;

                        if (handshakeMessage.isDtlsHandshakeMessageFragment()) {
                            messageFragments =
                                Collections.singletonList((DtlsHandshakeMessageFragment) handshakeMessage);
                        } else {
                            messageFragments = fragmenter.fragmentMessage(handshakeMessage, context);
                        }

                        for (DtlsHandshakeMessageFragment fragment : messageFragments) {
                            messageBytesCollector
                                .appendProtocolMessageBytes(fragment.getCompleteResultingMessage().getValue());
                            fragmentMessages.add(fragment);
                            recordPosition =
                                flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
                        }
                    } else {
                        messageBytesCollector.appendProtocolMessageBytes(protocolMessageBytes);
                    }
                } else {
                    messageBytesCollector.appendProtocolMessageBytes(protocolMessageBytes);
                }
            }
            if (context.getConfig().isCreateIndividualRecords()) {
                recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
                if (protocolMessage instanceof TlsMessage && protocolMessage.getAdjustContext()) {
                    TlsMessageHandler<TlsMessage> protocolMessageHandler = protocolMessage.getHandler(context);
                    protocolMessageHandler.adjustTlsContextAfterSerialize((TlsMessage) protocolMessage);
                }
                lastMessage = null;
            }
        }
        recordPosition = flushBytesToRecords(messageBytesCollector, lastType, records, recordPosition, context);
        if (lastMessage instanceof TlsMessage && lastMessage.getAdjustContext()) {
            TlsMessageHandler<TlsMessage> handler = lastMessage.getHandler(context);
            handler.adjustTlsContextAfterSerialize((TlsMessage) lastMessage);
        }
        sendData(messageBytesCollector, context);
        if (context.getConfig().isUseAllProvidedRecords() && recordPosition < records.size()) {
            int current = 0;
            for (AbstractRecord record : records) {
                if (current >= recordPosition) {
                    if (record.getMaxRecordLengthConfig() == null) {
                        record.setMaxRecordLengthConfig(context.getConfig().getDefaultMaxRecordData());
                    }
                    List<AbstractRecord> emptyRecords = new LinkedList<>();
                    emptyRecords.add(record);
                    messageBytesCollector.appendRecordBytes(
                        context.getRecordLayer().prepareRecords(messageBytesCollector.getProtocolMessageBytesStream(),
                            record.getContentMessageType(), emptyRecords));
                    sendData(messageBytesCollector, context);
                }
                current++;
            }
        }
        if (fragmentMessages.isEmpty()) {
            fragmentMessages = null;
        }
        return new MessageActionResult(records, messages, fragmentMessages);
    }

    public void sendRecords(List<AbstractRecord> records, TlsContext context) throws IOException {

        context.setTalkingConnectionEndType(context.getChooser().getConnectionEndType());

        if (records == null) {
            LOGGER.debug("No records specified, nothing to send");
            return;
        }

        MessageBytesCollector messageBytesCollector = new MessageBytesCollector();

        for (AbstractRecord record : records) {
            messageBytesCollector.appendRecordBytes(record.getRecordSerializer().serialize());
        }
        LOGGER.debug("Sending " + records.size() + "records");
        sendData(messageBytesCollector, context);
    }

    private int flushBytesToRecords(MessageBytesCollector collector, ProtocolMessageType type,
        List<AbstractRecord> records, int recordPosition, TlsContext context) {
        int length = collector.getProtocolMessageBytesStream().length;
        List<AbstractRecord> toFillList = getEnoughRecords(length, recordPosition, records, context);
        collector.appendRecordBytes(
            context.getRecordLayer().prepareRecords(collector.getProtocolMessageBytesStream(), type, toFillList));
        collector.flushProtocolMessageBytes();
        return recordPosition + toFillList.size();
    }

    private List<AbstractRecord> getEnoughRecords(int length, int position, List<AbstractRecord> records,
        TlsContext context) {
        List<AbstractRecord> toFillList = new LinkedList<>();
        int recordLength = 0;
        while (recordLength < length) {
            if (position >= records.size()) {
                if (context.getConfig().isCreateRecordsDynamically()) {
                    LOGGER.trace("Creating new Record");
                    records.add(context.getRecordLayer().getFreshRecord());
                    if (context.getConfig().getDefaultMaxRecordData() == 0) {
                        LOGGER.warn("MaxRecordLength is 0 in config. This is an endless loop. Aborting");
                        break;
                    }
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
     * Sends all messageBytes in the MessageByteCollector with the specified TransportHandler
     *
     * @param  collector
     *                     MessageBytes to send
     * @throws IOException
     *                     Thrown if something goes wrong while sending
     */
    private void sendData(MessageBytesCollector collector, TlsContext context) throws IOException {
        context.getTransportHandler().sendData(collector.getRecordBytes());
        collector.flushRecordBytes();
    }

    /**
     * Prepare message for sending. This method invokes before and after method hooks.
     *
     * @param  message
     *                 The Message that should be prepared
     * @return         message in bytes
     */
    public static byte[] prepareMessage(ProtocolMessage message, TlsContext context) {
        return prepareMessage(message, true, context);
    }

    /**
     * Prepare message for sending. This method invokes before and after method hooks.
     *
     * @param  message
     *                     The message that should be prepared
     * @param  withPrepare
     *                     if the prepare function should be called or only the rest
     * @return             message in bytes
     */
    public static byte[] prepareMessage(ProtocolMessage message, boolean withPrepare, TlsContext context) {
        if (withPrepare) {
            Preparator<ProtocolMessage> preparator = message.getHandler(context).getPreparator(message);
            preparator.prepare();
            preparator.afterPrepare();
            Serializer<ProtocolMessage> serializer = message.getHandler(context).getSerializer(message);
            byte[] completeMessage = serializer.serialize();
            message.setCompleteResultingMessage(completeMessage);
        }
        try {
            if (message.getAdjustContext()) {
                if (context.getConfig().getDefaultSelectedProtocolVersion().isDTLS()
                    && (message instanceof HandshakeMessage)
                    && !((HandshakeMessage) message).isDtlsHandshakeMessageFragment()) {
                    context.increaseDtlsWriteHandshakeMessageSequence();
                }
            }

            if (message instanceof TlsMessage) {
                TlsMessageHandler<TlsMessage> handler = message.getHandler(context);
                handler.updateDigest(message);
            }
            if (message.getAdjustContext()) {

                message.getHandler(context).adjustContext(message);
            }
        } catch (AdjustmentException e) {
            LOGGER.warn("Could not adjust TLSContext");
            LOGGER.debug(e);
        }

        return message.getCompleteResultingMessage().getValue();
    }
}
