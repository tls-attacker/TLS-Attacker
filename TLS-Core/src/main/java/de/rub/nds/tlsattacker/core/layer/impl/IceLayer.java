/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.ice.handler.IceMessageHandler;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;
import de.rub.nds.tlsattacker.core.ice.model.DataAttribute;
import de.rub.nds.tlsattacker.core.ice.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.ice.model.IceMessage;
import de.rub.nds.tlsattacker.core.ice.model.SoftwareAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.ice.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A Layer that implements STUN/TURN & TURN ChannelMessages for ICE */
public class IceLayer extends ProtocolLayer<RecordLayerHint, IceMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private Context context;

    public IceLayer(Context context) {
        super(ImplementedLayers.ICE);
        this.context = context;
    }

    @Override
    public LayerProcessingResult<IceMessage> sendConfiguration() throws IOException {
        if (getLayerConfiguration().getContainerList() != null) {
            for (IceMessage message : getLayerConfiguration().getContainerList()) {
                prepareDataContainer(message, context);
                IceMessageHandler handler = message.getHandler(context);
                handler.adjustContext(message);
                message.setCompleteMessageBytes(
                        message.getSerializer(context).serialize());
                getLowerLayer().sendData(null, message.getCompleteMessageBytes().getValue());
                addProducedContainer(message);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult<IceMessage> sendData(
            LayerProcessingHint hint, byte[] additionalData) {
        // TODO Fix Fragmentation if data is too big
        try {

            if (additionalData.length > 0xFFFF) { // TODO Fix number
                LOGGER.warn(
                        "Data is too big for a single STUN message. Fragmentation is not yet implemented.");
            }
            if (context.getIceContext().getIceConnectionEndType() == null) {
                LOGGER.warn("Connection end type is not set. Assuming client.");
                context.getIceContext().setIceConnectionEndType(ConnectionEndType.CLIENT);
            }

            if (context.getIceContext().getTurnDataChannel() != null) {
                sendAsChannelData(additionalData);
            } else {
                sendAsTurnOverStun(additionalData);
            }
            return getLayerResult();
        } catch (IOException e) {
            LOGGER.warn("Could not send data", e);
            return getLayerResult();
        }
    }

    private void sendAsChannelData(byte[] additionalData) throws IOException {
        LOGGER.trace("Sending data as TURN channel data");
        ChannelDataMessage message = new ChannelDataMessage(additionalData);
        prepareDataContainer(message, context);
        message.getHandler(context).adjustContext(message);
        message.setCompleteMessageBytes(message.getSerializer(context).serialize());
        getLowerLayer().sendData(null, message.getCompleteMessageBytes().getValue());
        addProducedContainer(message);
    }

    private void sendAsTurnOverStun(byte[] additionalData) throws IOException {
        StunMessage message;
        if (context.getIceContext().getIceConnectionEndType() == ConnectionEndType.CLIENT) {
            LOGGER.trace("Sending data as a STUN/TURN client");
            message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.SEND);
            message.getAttributeList().add(new XorPeerAddressAttribute());
            message.getAttributeList().add(new DataAttribute(additionalData));
            message.getAttributeList().add(new FingerprintAttribute());
        } else {
            LOGGER.trace("Sending data as a STUN/TURN server");
            message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.DATA);
            message.getAttributeList().add(new DataAttribute(additionalData));
            message.getAttributeList().add(new XorPeerAddressAttribute());
            message.getAttributeList().add(new SoftwareAttribute());
            message.getAttributeList().add(new FingerprintAttribute());
        }
        prepareDataContainer(message, iceContext.getContext());
        message.getHandler(iceContext.getContext()).adjustContext(message);
        message.setCompleteMessageBytes(message.getSerializer(iceContext.getContext()).serialize());
        getLowerLayer().sendData(null, message.getCompleteMessageBytes().getValue());
        addProducedContainer(message);
    }

    @Override
    public LayerProcessingResult<IceMessage> receiveData() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        HintedInputStream dataStream = getLowerLayer().getDataStream();
        // Peek to get the type
        while (dataStream.available() > 0) {
            byte[] firstTwobytes = dataStream.readChunk(IceByteLengths.STUN_MESSAGE_TYPE);
            if (firstTwobytes[0] >= 64 && firstTwobytes[0] <= 79) {
                LOGGER.trace("Reading as TURN ChannelData message");
                receiveTurnChannelData(hint, dataStream, firstTwobytes);
            } else {
                LOGGER.trace("Reading as STUN/TURN message");
                receiveStunMessage(hint, dataStream, firstTwobytes);
            }
        }
    }

    private void receiveTurnChannelData(
            LayerProcessingHint hint, HintedInputStream dataStream, byte[] firstTwobytes)
            throws IOException {
        byte[] channelNumber;
        byte[] lengthBytes;
        if (iceContext.getLayerStack().getLowestLayer() instanceof TcpLayer) {
            // If we are using TCP, we do not need to read the channel number
            channelNumber = new byte[0];
            lengthBytes = firstTwobytes;
        } else {
            // We are using UDP, so the first two bytes are the channel number followed by
            // the
            // length
            channelNumber = firstTwobytes;
            lengthBytes = dataStream.readChunk(IceByteLengths.TURN_CHANNEL_DATA_LENGTH);
        }
        int length = ArrayConverter.bytesToInt(lengthBytes);
        byte[] data = dataStream.readChunk(length);
        int paddingLength = 0;
        if (dataStream.available() > 0) {
            paddingLength =
                    (IceByteLengths.DATA_CHANNEL_ALIGNMENT
                                    - (length) % IceByteLengths.DATA_CHANNEL_ALIGNMENT)
                            % IceByteLengths.DATA_CHANNEL_ALIGNMENT;
            if (paddingLength < 0) {
                paddingLength = 0;
            }
        }
        byte[] padding = dataStream.readChunk(paddingLength);
        byte[] completeMessageBytes =
                ArrayConverter.concatenate(channelNumber, lengthBytes, data, padding);
        ChannelDataMessage message = new ChannelDataMessage(data);
        message.setCompleteMessageBytes(completeMessageBytes);
        readDataContainer(
                message, iceContext.getContext(), new ByteArrayInputStream(completeMessageBytes));
        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(hint, this);
        }
        currentInputStream.extendStream(message.getData().getValue());
    }

    private void receiveStunMessage(
            LayerProcessingHint hint, HintedInputStream dataStream, byte[] firstTwobytes)
            throws IOException {
        byte[] typeBytes = firstTwobytes;
        byte[] lengthBytes = dataStream.readChunk(IceByteLengths.STUN_MESSAGE_LENGTH);
        int length = ArrayConverter.bytesToInt(lengthBytes) + IceByteLengths.STUN_TRANSACTION_ID;
        byte[] body = dataStream.readChunk(length);
        byte[] fullMessage = ArrayConverter.concatenate(typeBytes, lengthBytes, body);
        StunMethodType methodType = StunMethodType.getStunMethodTypeFromRawBytes(typeBytes);
        StunMessageClass messageClass = StunMessageClass.getMessageClass(typeBytes);
        StunMessage stunMessage = new StunMessage(messageClass, methodType);
        stunMessage.setCompleteMessageBytes(fullMessage);
        readDataContainer(
                stunMessage, iceContext.getContext(), new ByteArrayInputStream(fullMessage));
        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(hint, this);
        }
        for (StunAttribute attribute : stunMessage.getAttributeList()) {
            if (attribute.getType() == StunAttributeType.DATA) {
                DataAttribute dataAttribute = (DataAttribute) attribute;
                LOGGER.debug(
                        "Received DATA for upper layer: {}", dataAttribute.getData().getValue());
                currentInputStream.extendStream(dataAttribute.getData().getValue());
            }
        }
    }
}
