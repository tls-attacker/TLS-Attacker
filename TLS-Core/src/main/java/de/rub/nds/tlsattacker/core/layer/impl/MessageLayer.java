/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.TimeoutException;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.QuicFrameLayerHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The MessageLayer handles TLS Handshake messages. The encapsulation into records happens in the
 * {@link RecordLayer}.
 */
public class MessageLayer extends ProtocolLayer<Context, LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final TlsContext tlsContext;

    public MessageLayer(Context context) {
        super(ImplementedLayers.MESSAGE);
        this.context = context;
        this.tlsContext = context.getTlsContext();
    }

    /**
     * Sends the given handshake messages using the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the sent data.
     * @throws IOException When the data cannot be sent.
     */
    @Override
    public LayerProcessingResult<ProtocolMessage> sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        ProtocolMessageType runningProtocolMessageType = null;
        List<byte[]> bufferedMessages = new LinkedList<>();
        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : getUnprocessedConfiguredContainers()) {
                if (containerAlreadyUsedByHigherLayer(message)
                        || !prepareDataContainer(message, context)) {
                    continue;
                }
                if (!message.isHandshakeMessage()) {
                    // only handshake messages may share a record
                    flushCollectedMessages(runningProtocolMessageType, bufferedMessages, false);
                }
                runningProtocolMessageType = message.getProtocolMessageType();
                processMessage(message, bufferedMessages);
                addProducedContainer(message);
            }
        }
        // hand remaining serialized to record layer
        flushCollectedMessages(runningProtocolMessageType, bufferedMessages, false);
        return getLayerResult();
    }

    private void processMessage(ProtocolMessage message, List<byte[]> bufferedMessages)
            throws IOException {
        ProtocolMessageSerializer<? extends ProtocolMessage> serializer =
                message.getSerializer(context);
        byte[] serializedMessage = serializer.serialize();
        message.setCompleteResultingMessage(serializedMessage);
        ProtocolMessageHandler handler = message.getHandler(context);
        handler.updateDigest(message, true);
        if (message.getAdjustContext()) {
            handler.adjustContext(message);
        }
        bufferedMessages.add(message.getCompleteResultingMessage().getValue());
        if (mustFlushCollectedMessagesImmediately(message)) {
            boolean isFirstMessage =
                    (message instanceof CoreClientHelloMessage
                            || message.getClass() == ServerHelloMessage.class);
            flushCollectedMessages(
                    message.getProtocolMessageType(), bufferedMessages, isFirstMessage);
        }
        if (message.getAdjustContext()) {
            handler.adjustContextAfterSerialize(message);
        }
    }

    private void flushCollectedMessages(
            ProtocolMessageType runningProtocolMessageType,
            List<byte[]> bufferedMessages,
            boolean isFirstMessage)
            throws IOException {
        if (bufferedMessages.size() > 0) {
            byte[] allBufferedMessageBytes = collectBufferedBytes(bufferedMessages);
            LOGGER.debug(
                    "Handing {} serialized message(s) ({} bytes) down to lower layer",
                    bufferedMessages.size(),
                    allBufferedMessageBytes.length);
            if (context.getLayerStack().getLayer(QuicFrameLayer.class) != null) {
                getLowerLayer()
                        .sendData(
                                new QuicFrameLayerHint(runningProtocolMessageType, isFirstMessage),
                                allBufferedMessageBytes);
            } else {
                getLowerLayer()
                        .sendData(
                                new RecordLayerHint(runningProtocolMessageType),
                                allBufferedMessageBytes);
            }
            bufferedMessages.clear();
        }
    }

    private byte[] collectBufferedBytes(List<byte[]> bufferedMessages) {
        SilentByteArrayOutputStream byteStream = new SilentByteArrayOutputStream();
        for (byte[] message : bufferedMessages) {
            byteStream.write(message);
        }
        return byteStream.toByteArray();
    }

    /**
     * Determine if the current message must be flushed with all possibly previously collected. This
     * mostly avoids cases where the message updates the crypto state but must be sent with old
     * state.
     *
     * @param message
     * @return true if must be flushed
     */
    private boolean mustFlushCollectedMessagesImmediately(ProtocolMessage message) {
        if (!context.getConfig().getSendHandshakeMessagesWithinSingleRecord()) {
            // if any, handshake messages are the only messages we put in a single record
            return true;
        } else if (message.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
            // CCS is the only message for its content type, so we can/must always flush immediately
            return true;
        } else if (message.isHandshakeMessage()
                && (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13)) {
            // TODO: add DTLS 1.3 above once implemented
            HandshakeMessage handshakeMessage = (HandshakeMessage) message;
            if (handshakeMessage.getHandshakeMessageType() == HandshakeMessageType.SERVER_HELLO) {
                // we must flush to avoid encrypting the SH later on
                return !((ServerHelloMessage) message).hasTls13HelloRetryRequestRandom();
            } else if (handshakeMessage.getHandshakeMessageType() == HandshakeMessageType.FINISHED
                    || handshakeMessage.getHandshakeMessageType() == HandshakeMessageType.KEY_UPDATE
                    || handshakeMessage.getHandshakeMessageType()
                            == HandshakeMessageType.END_OF_EARLY_DATA) {
                return true;
            } else if (handshakeMessage.getHandshakeMessageType()
                            == HandshakeMessageType.CLIENT_HELLO
                    && context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                    && tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public LayerProcessingResult<ProtocolMessage> sendData(
            LayerProcessingHint hint, byte[] additionalData) throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        ApplicationMessage applicationMessage = getConfiguredApplicationMessage(configuration);
        if (applicationMessage == null) {
            applicationMessage = new ApplicationMessage();
        } else if (applicationMessage.getDataConfig() != null) {
            LOGGER.warn(
                    "Found Application message with pre configured content while sending HTTP message. Configured content will be replaced.");
        }
        applicationMessage.setDataConfig(additionalData);
        if (context.getLayerStack().getLayer(QuicFrameLayer.class) != null) {
            getLowerLayer()
                    .sendData(
                            new QuicFrameLayerHint(ProtocolMessageType.APPLICATION_DATA),
                            additionalData);
        } else {
            getLowerLayer()
                    .sendData(
                            new RecordLayerHint(ProtocolMessageType.APPLICATION_DATA),
                            additionalData);
        }

        addProducedContainer(applicationMessage);
        return getLayerResult();
    }

    public ApplicationMessage getConfiguredApplicationMessage(
            LayerConfiguration<ProtocolMessage> configuration) {
        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage configuredMessage : getUnprocessedConfiguredContainers()) {
                if (configuredMessage.getProtocolMessageType()
                        == ProtocolMessageType.APPLICATION_DATA) {
                    return (ApplicationMessage) configuredMessage;
                }
            }
        }
        return null;
    }

    /**
     * Receives handshake message from the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the received data.
     */
    @Override
    public LayerProcessingResult<ProtocolMessage> receiveData() {
        try {
            HintedInputStream dataStream;
            do {
                try {
                    dataStream = getLowerLayer().getDataStream();
                    if (dataStream.available() == 0) {
                        // the lower layer does not give us any data so we can simply return here
                        LOGGER.warn("The lower layer did not produce any data.");
                        return getLayerResult();
                    }
                } catch (IOException e) {
                    // the lower layer does not give us any data so we can simply return here
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                LayerProcessingHint tempHint = dataStream.getHint();
                if (tempHint == null) {
                    LOGGER.warn(
                            "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                } else if (tempHint instanceof RecordLayerHint) {
                    RecordLayerHint hint = (RecordLayerHint) dataStream.getHint();
                    readMessageForHint(hint);
                }
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug("Received a timeout");
            LOGGER.trace(ex);
            setReachedTimeout(true);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages");
            LOGGER.trace(ex);
        }

        return getLayerResult();
    }

    public void readMessageForHint(RecordLayerHint hint) {
        switch (hint.getType()) {
            case ALERT:
                readAlertProtocolData();
                break;
            case APPLICATION_DATA:
                readAppDataProtocolData();
                break;
            case CHANGE_CIPHER_SPEC:
                readCcsProtocolData(hint.getEpoch());
                break;
            case HANDSHAKE:
                readHandshakeProtocolData();
                break;
            case HEARTBEAT:
                readHeartbeatProtocolData();
                break;
            case ACK:
                readAckProtocolData();
                break;
            case UNKNOWN:
                readUnknownProtocolData();
                break;
            default:
                readUnknownProtocolData();
                LOGGER.warn(
                        "Undefined record layer type ({})",
                        (hint.getType() == null ? "null" : hint.getType()));
                break;
        }
    }

    private void readAlertProtocolData() {
        AlertMessage message = new AlertMessage();
        readDataContainer(message, context);
    }

    private ApplicationMessage readAppDataProtocolData() {
        ApplicationMessage message = new ApplicationMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
        return message;
    }

    private void readCcsProtocolData(Integer epoch) {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        if (tlsContext.getSelectedProtocolVersion() != null
                && tlsContext.getSelectedProtocolVersion().isDTLS()) {
            if (tlsContext.getDtlsReceivedChangeCipherSpecEpochs().contains(epoch)
                    && tlsContext.getConfig().isIgnoreRetransmittedCcsInDtls()) {
                message.setAdjustContext(false);
            } else {
                tlsContext.addDtlsReceivedChangeCipherSpecEpochs(epoch);
            }
        }
        readDataContainer(message, context);
    }

    /**
     * Parses the handshake layer header from the given message and parses the encapsulated message
     * using the correct parser.
     *
     * @throws IOException
     */
    private void readHandshakeProtocolData() {
        SilentByteArrayOutputStream readBytesStream = new SilentByteArrayOutputStream();
        byte type;
        int length;
        byte[] payload;
        HandshakeMessage handshakeMessage;
        HintedInputStream handshakeStream;
        try {
            handshakeStream = getLowerLayer().getDataStream();
            type = handshakeStream.readByte();
            readBytesStream.write(new byte[] {type});
            handshakeMessage =
                    MessageFactory.generateHandshakeMessage(
                            HandshakeMessageType.getMessageType(type), tlsContext);
            handshakeMessage.setType(type);
            byte[] lengthBytes =
                    handshakeStream.readChunk(HandshakeByteLength.MESSAGE_LENGTH_FIELD);
            length = DataConverter.bytesToInt(lengthBytes);
            readBytesStream.write(lengthBytes);
            handshakeMessage.setLength(length);
            payload = handshakeStream.readChunk(length);
            readBytesStream.write(payload);

        } catch (IOException ex) {
            LOGGER.error("Could not parse message header. Setting bytes as unread: ", ex);
            // not being able to parse the header leaves us with unreadable bytes
            // append instead of replace because we can read multiple messages in one read action
            setUnreadBytes(
                    DataConverter.concatenate(
                            this.getUnreadBytes(), readBytesStream.toByteArray()));
            return;
        }
        HandshakeMessageHandler handler = handshakeMessage.getHandler(context);
        handshakeMessage.setMessageContent(payload);

        try {
            handshakeMessage.setCompleteResultingMessage(
                    DataConverter.concatenate(
                            new byte[] {type},
                            DataConverter.intToBytes(
                                    length, HandshakeByteLength.MESSAGE_LENGTH_FIELD),
                            payload));
            HandshakeMessageParser parser =
                    handshakeMessage.getParser(context, new ByteArrayInputStream(payload));
            parser.parse(handshakeMessage);
            Preparator preparator = handshakeMessage.getPreparator(context);
            preparator.prepareAfterParse();
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                handshakeMessage.setMessageSequence(
                        ((RecordLayerHint) handshakeStream.getHint()).getMessageSequence());
            }
            handler.updateDigest(handshakeMessage, false);
            handler.adjustContext(handshakeMessage);
            addProducedContainer(handshakeMessage);
        } catch (RuntimeException ex) {
            LOGGER.warn(
                    "Failed to parse HandshakeMessage using assumed type {}",
                    HandshakeMessageType.getMessageType(type));
            LOGGER.trace(ex);
            // not being able to handle the handshake message results in an UnknownMessageContainer
            UnknownHandshakeMessage message = new UnknownHandshakeMessage();
            message.setAssumedType(type);
            message.setData(payload);
            addProducedContainer(message);
        }
    }

    private void readHeartbeatProtocolData() {
        HeartbeatMessage message = new HeartbeatMessage();
        readDataContainer(message, context);
    }

    private void readAckProtocolData() {
        AckMessage message = new AckMessage();
        readDataContainer(message, context);
    }

    private void readUnknownProtocolData() {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) {
        boolean continueProcessing;

        do {
            try {
                HintedInputStream dataStream;
                try {
                    dataStream = getLowerLayer().getDataStream();
                } catch (IOException e) {
                    // the lower layer does not give us any data, so we can simply return here
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return;
                }
                // for now, we ignore the hint as we only expect app data to be
                // requested anyway
                LayerProcessingHint inputStreamHint = dataStream.getHint();
                if (inputStreamHint == null) {
                    // TODO: determine if this should be passed to upper layer
                    LOGGER.warn(
                            "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                    continueProcessing = false;
                } else if (inputStreamHint instanceof RecordLayerHint) {
                    RecordLayerHint recordLayerHint = (RecordLayerHint) inputStreamHint;
                    if (recordLayerHint.getType() == ProtocolMessageType.APPLICATION_DATA) {
                        ApplicationMessage receivedAppData = readAppDataProtocolData();
                        passToHigherLayer(receivedAppData, hint);
                        continueProcessing = false;
                    } else {
                        readMessageForHint(recordLayerHint);
                        continueProcessing = true;
                    }
                } else {
                    continueProcessing = false;
                }
                // receive until the layer configuration is satisfied or no data is left
            } catch (TimeoutException ex) {
                LOGGER.debug("Received a timeout");
                LOGGER.trace(ex);
                continueProcessing = false;
            } catch (EndOfStreamException ex) {
                LOGGER.debug("Reached end of stream, cannot parse more messages");
                LOGGER.trace(ex);
                continueProcessing = false;
            }
        } while (continueProcessing);
    }

    public void passToHigherLayer(ApplicationMessage receivedAppData, LayerProcessingHint hint) {
        LOGGER.debug(
                "Passing the following Application Data to higher layer: {}",
                receivedAppData.getData().getValue());
        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(hint, this);
        } else {
            currentInputStream.setHint(hint);
        }
        currentInputStream.extendStream(receivedAppData.getData().getValue());
    }
}
