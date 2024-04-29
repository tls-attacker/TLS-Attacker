/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import de.rub.nds.tlsattacker.core.stun.model.XorPeerAddressAttribute;

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
            message.getPreparator(context).prepare();
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

            if (additionalData.length > 0xFFFF) {
                LOGGER.warn("Data is too big for a single STUN message. Fragmentation is not yet implemented.");
            }
            StunMessage message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.DATA);
            message.getAttributeList().add(new DataAttribute(additionalData));
            message.getAttributeList().add(new XorPeerAddressAttribute());
            message.getAttributeList().add(new FingerprintAttribute());
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
        byte[] data = dataStream.readAllBytes();
        if (data.length < 2) {
            LOGGER.warn("Not enough data in the stream to parse a StunMessage");
            return;
        }
        //Peek to get the type
        byte[] typeBytes = Arrays.copyOf(data, IceByteLengths.STUN_MESSAGE_TYPE);
        StunMethodType methodType = StunMethodType.getStunMethodTypeFromRawBytes(typeBytes);
        StunMessageClass messageClass = StunMessageClass.getMessageClass(typeBytes);
        StunMessage stunMessage = new StunMessage(messageClass, methodType);
        readDataContainer(stunMessage, context);
    }
}
