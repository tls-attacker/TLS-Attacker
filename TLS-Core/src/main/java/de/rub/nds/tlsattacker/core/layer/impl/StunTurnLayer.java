/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.stun.model.SoftwareAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import de.rub.nds.tlsattacker.core.stun.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class StunTurnLayer extends ProtocolLayer<RecordLayerHint, StunMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private IceContext context;

    public StunTurnLayer(IceContext context) {
        super(ImplementedLayers.STUN_TURN);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        for (StunMessage message : getLayerConfiguration().getContainerList()) {
            prepareDataContainer(message, context);
            message.getHandler(context).adjustContext(message);
            message.setCompleteMessageBytes(message.getSerializer(context).serialize());
            getLowerLayer().sendData(null, message.getCompleteMessageBytes().getValue());
            addProducedContainer(message);
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(RecordLayerHint hint, byte[] additionalData) {
        //TODO Fix Fragmentation if data is too big
        try {

            if (additionalData.length > 0xFFFF) { //TODO Fix number
                LOGGER.warn("Data is too big for a single STUN message. Fragmentation is not yet implemented.");
            }
            if(context.getIceConnectionEndType() == null) {
                LOGGER.warn("Connection end type is not set. Assuming client.");
                context.setIceConnectionEndType(ConnectionEndType.CLIENT);
            }

            StunMessage message;
            if (context.getIceConnectionEndType() == ConnectionEndType.CLIENT) {
                message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.SEND);
                message.getAttributeList().add(new XorPeerAddressAttribute());
                message.getAttributeList().add(new DataAttribute(additionalData));
                message.getAttributeList().add(new FingerprintAttribute());
            } else {
                message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.DATA);
                message.getAttributeList().add(new DataAttribute(additionalData));
                message.getAttributeList().add(new XorPeerAddressAttribute());
                message.getAttributeList().add(new SoftwareAttribute());
                message.getAttributeList().add(new FingerprintAttribute());
            
            }
            message.getPreparator(context).prepare();
            message.getHandler(context).adjustContext(message);
            message.setCompleteMessageBytes(message.getSerializer(context).serialize());
            getLowerLayer().sendData(null, message.getCompleteMessageBytes().getValue());

            addProducedContainer(message);

            return getLayerResult();
        } catch (IOException e) {
            LOGGER.warn("Could not send data", e);
            return getLayerResult();
        }
    }

    @Override
    public LayerProcessingResult receiveData() {
        throw new UnsupportedOperationException(
                "Not supported yet.");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        HintedInputStream dataStream = getLowerLayer().getDataStream();
        //Peek to get the type
        while (dataStream.available() > 0) {

            byte[] typeBytes = dataStream.readChunk(IceByteLengths.STUN_MESSAGE_TYPE);
            byte[] lengthBytes = dataStream.readChunk(IceByteLengths.STUN_MESSAGE_LENGTH);
            int length = ArrayConverter.bytesToInt(lengthBytes) + IceByteLengths.STUN_TRANSACTION_ID;
            byte[] body = dataStream.readChunk(length);
            byte[] fullMessage = ArrayConverter.concatenate(typeBytes, lengthBytes, body);
            StunMethodType methodType = StunMethodType.getStunMethodTypeFromRawBytes(typeBytes);
            StunMessageClass messageClass = StunMessageClass.getMessageClass(typeBytes);
            StunMessage stunMessage = new StunMessage(messageClass, methodType);
            stunMessage.setCompleteMessageBytes(fullMessage);
            readDataContainer(stunMessage, context, new ByteArrayInputStream(fullMessage));
            if (currentInputStream == null) {
                currentInputStream = new HintedLayerInputStream(hint, this);
            }
            for (StunAttribute attribute : stunMessage.getAttributeList()) {
                if (attribute.getType() == StunAttributeType.DATA) {
                    DataAttribute dataAttribute = (DataAttribute) attribute;
                    LOGGER.debug("Received DATA for upper layer: {}", dataAttribute.getData().getValue());
                    currentInputStream.extendStream(dataAttribute.getData().getValue());
                }
            }
        }
    }
}
