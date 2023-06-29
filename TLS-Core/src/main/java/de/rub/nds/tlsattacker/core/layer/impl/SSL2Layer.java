/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2TotalHeaderLengths;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2Layer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private TlsContext context;

    public SSL2Layer(TlsContext context) {
        super(ImplementedLayers.SSL2);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        if (configuration != null && !configuration.getContainerList().isEmpty()) {
            for (ProtocolMessage ssl2message : configuration.getContainerList()) {
                ProtocolMessagePreparator preparator = ssl2message.getPreparator(context);
                preparator.prepare();
                preparator.afterPrepare();
                ssl2message.getHandler(context).adjustContext(ssl2message);
                ProtocolMessageSerializer serializer = ssl2message.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                ssl2message.setCompleteResultingMessage(serializedMessage);
                ssl2message.getHandler(context).adjustContextAfterSerialize(ssl2message);
                ssl2message.getHandler(context).updateDigest(ssl2message, true);
                getLowerLayer()
                        .sendData(
                                new RecordLayerHint(ssl2message.getProtocolMessageType()),
                                serializedMessage);
                addProducedContainer(ssl2message);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData)
            throws IOException {
        return sendConfiguration();
    }

    @Override
    public LayerProcessingResult receiveData() {

        try {
            int messageLength = 0;
            byte paddingLength = 0;
            byte[] totalHeader;
            HintedInputStream dataStream = null;
            SSL2MessageType messageType;
            try {

                dataStream = getLowerLayer().getDataStream();
                totalHeader = dataStream.readNBytes(SSL2ByteLength.LENGTH);

                if (SSL2TotalHeaderLengths.isNoPaddingHeader(totalHeader[0])) {
                    messageLength = resolveUnpaddedMessageLength(totalHeader);
                    paddingLength = 0x00;
                } else {
                    messageLength = resolvePaddedMessageLength(totalHeader);
                    paddingLength = dataStream.readByte();
                }
                messageType = SSL2MessageType.getMessageType(dataStream.readByte());
            } catch (IOException e) {
                LOGGER.warn(
                        "Failed to parse SSL2 message header, parsing as unknown SSL2 message", e);
                messageType = SSL2MessageType.SSL_UNKNOWN;
            }

            SSL2Message message = null;

            switch (messageType) {
                case SSL_CLIENT_HELLO:
                    message = new SSL2ClientHelloMessage();
                    break;
                case SSL_CLIENT_MASTER_KEY:
                    message = new SSL2ClientMasterKeyMessage();
                    break;
                case SSL_SERVER_VERIFY:
                    message = new SSL2ServerVerifyMessage();
                    break;
                case SSL_SERVER_HELLO:
                    message = new SSL2ServerHelloMessage();
                    break;
                default:
                    message = new UnknownSSL2Message();
            }

            message.setType((byte) messageType.getType());
            message.setMessageLength(messageLength);
            message.setPaddingLength((int) paddingLength);
            readDataContainer(message, context);

        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
        }

        return getLayerResult();
    }

    private static int resolvePaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_TWO_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }

    private static int resolveUnpaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_ONE_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
