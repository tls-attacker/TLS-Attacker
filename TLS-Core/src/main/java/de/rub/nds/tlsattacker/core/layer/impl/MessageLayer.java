/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MessageLayer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public MessageLayer(TlsContext context) {
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        for (ProtocolMessage message : configuration.getContainerList()) {
            ProtocolMessagePreparator preparator = message.getPreparator(context);
            preparator.prepare();
            ProtocolMessageSerializer serializer = message.getSerializer(context);
            byte[] serializedMessage = serializer.serialize();

            getLowerLayer().sendData(new RecordLayerHint(message.getProtocolMessageType()), serializedMessage);
            addProducedContainer(message);
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

    @Override
    public void preInititialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void inititialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public LayerProcessingResult receiveData() throws IOException {
        HintedInputStream dataStream = getLowerLayer().getDataStream();
        if (dataStream.available() > 0) {
            LayerProcessingHint tempHint = dataStream.getHint();
            if (tempHint == null) {
                LOGGER.warn(
                    "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
            } else if (tempHint instanceof RecordLayerHint) {
                RecordLayerHint hint = (RecordLayerHint) dataStream.getHint();
                switch (hint.getType()) {
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
            } else {
                LOGGER.warn("Incompatible LayerProcessing hint. Parsing as unknown message");
            }
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

    }

    private void readCcsProtocolData() throws IOException {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        readDataContainer(message, context);
    }

    private void readHandshakeProtocolData() throws IOException {
        do {

            byte type = getLowerLayer().getDataStream().readByte();
            HandshakeMessageType handshakeMessageType = HandshakeMessageType.getMessageType(type);
            int length = getLowerLayer().getDataStream().readInt(HandshakeByteLength.MESSAGE_LENGTH_FIELD);
            HandshakeMessage handshakeMessage = MessageFactory.generateHandshakeMessage(handshakeMessageType, context);
            handshakeMessage.setType(type);
            handshakeMessage.setLength(length);
            readDataContainer(handshakeMessage, context);
        } while (getLowerLayer().getDataStream().available() > 0);
    }

    private void readHeartbeatProtocolData() throws IOException {
        HeartbeatMessage message = new HeartbeatMessage();
        readDataContainer(message, context);
    }

    private void readUnknownProtocolData() throws IOException {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
                                                                       // Tools | Templates.
    }
}
