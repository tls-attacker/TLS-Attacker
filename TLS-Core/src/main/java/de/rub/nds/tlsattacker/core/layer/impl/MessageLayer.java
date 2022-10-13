/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.ReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The MessageLayer handles TLS Handshake messages. The encapsulation into records happens in the {@link RecordLayer}.
 */
public class MessageLayer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public MessageLayer(TlsContext context) {
        super(ImplementedLayers.MESSAGE);
        this.context = context;
    }

    /**
     * Sends the given handshake messages using the lower layer.
     * 
     * @return             LayerProcessingResult A result object containing information about the sent data.
     * @throws IOException
     *                     When the data cannot be sent.
     */
    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : configuration.getContainerList()) {
                ProtocolMessagePreparator preparator = message.getPreparator(context);
                preparator.prepare();
                preparator.afterPrepare();
                ProtocolMessageSerializer serializer = message.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                message.setCompleteResultingMessage(serializedMessage);
                message.getHandler(context).updateDigest(message, true);
                message.getHandler(context).adjustContext(message);
                getLowerLayer().sendData(new RecordLayerHint(message.getProtocolMessageType()), serializedMessage);
                message.getHandler(context).adjustContextAfterSerialize(message);
                addProducedContainer(message);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    @Override
    public HintedLayerInputStream getDataStream() {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    /**
     * Receives handshake message from the lower layer.
     * 
     * @return             LayerProcessingResult A result object containing information about the received data.
     * @throws IOException
     *                     When no data can be received
     */
    @Override
    public LayerProcessingResult receiveData() throws IOException {
        try {
            HintedInputStream dataStream = null;
            do {
                dataStream = getLowerLayer().getDataStream();
                LayerProcessingHint tempHint = dataStream.getHint();
                if (tempHint == null) {
                    LOGGER.warn(
                        "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                } else if (tempHint instanceof RecordLayerHint) {
                    RecordLayerHint hint = (RecordLayerHint) dataStream.getHint();
                    switch (hint.getType()) {
                        // use correct parser for the message
                        case ALERT:
                            readAlertProtocolData();
                            break;
                        case APPLICATION_DATA:
                            readAppDataProtocolData();
                            break;
                        case CHANGE_CIPHER_SPEC:
                            readCcsProtocolData();
                            break;
                        case HANDSHAKE:
                            readHandshakeProtocolData();
                            break;
                        case HEARTBEAT:
                            readHeartbeatProtocolData();
                            break;
                        case UNKNOWN:
                            readUnknownProtocolData();
                            break;
                        default:
                            LOGGER.error("Undefined record layer type");
                            break;
                    }
                }
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
        }

        return getLayerResult();
    }

    private void readAlertProtocolData() throws IOException {
        AlertMessage message = new AlertMessage();
        readDataContainer(message, context);
    }

    private void readAppDataProtocolData() throws IOException {
        ApplicationMessage message = new ApplicationMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    private void readCcsProtocolData() throws IOException {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        readDataContainer(message, context);
    }

    /**
     * Parses the handshake layer header from the given message and parses the encapsulated message using the correct
     * parser.
     * 
     * @throws IOException
     */
    private void readHandshakeProtocolData() throws IOException {
        HintedInputStream handshakeStream = getLowerLayer().getDataStream();
        byte type = handshakeStream.readByte();
        HandshakeMessage handshakeMessage =
            MessageFactory.generateHandshakeMessage(HandshakeMessageType.getMessageType(type), context);
        handshakeMessage.setType(type);
        int length = handshakeStream.readInt(HandshakeByteLength.MESSAGE_LENGTH_FIELD);
        handshakeMessage.setLength(length);
        byte[] payload = handshakeStream.readChunk(length);
        handshakeMessage.setMessageContent(payload);
        handshakeMessage.setCompleteResultingMessage(ArrayConverter.concatenate(new byte[] { type },
            ArrayConverter.intToBytes(length, HandshakeByteLength.MESSAGE_LENGTH_FIELD), payload));
        Parser parser = handshakeMessage.getParser(context, new ByteArrayInputStream(payload));
        parser.parse(handshakeMessage);
        Preparator preparator = handshakeMessage.getPreparator(context);
        preparator.prepareAfterParse(false);// TODO REMOVE THIS CLIENTMODE FLAG
        Handler handler = handshakeMessage.getHandler(context);
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            handshakeMessage.setMessageSequence(((RecordLayerHint) handshakeStream.getHint()).getMessageSequence());
        }
        handshakeMessage.getHandler(context).updateDigest(handshakeMessage, false);
        handler.adjustContext(handshakeMessage);
        addProducedContainer(handshakeMessage);
    }

    private void readHeartbeatProtocolData() throws IOException {
        HeartbeatMessage message = new HeartbeatMessage();
        readDataContainer(message, context);
    }

    private void readUnknownProtocolData() throws IOException {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
