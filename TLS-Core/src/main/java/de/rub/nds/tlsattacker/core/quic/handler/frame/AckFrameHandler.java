/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.frame;

import de.rub.nds.tlsattacker.core.layer.impl.QuicPacketLayer;
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import org.apache.logging.log4j.LogManager;

public class AckFrameHandler extends QuicFrameHandler<AckFrame> {

    public AckFrameHandler(QuicContext quicContext) {
        super(quicContext);
    }

    @Override
    public void adjustContext(AckFrame object) {
        QuicPacketLayer packetLayer =
                (QuicPacketLayer) quicContext.getLayerStack().getLayer(QuicPacketLayer.class);
        if (packetLayer == null) {
            LogManager.getLogger()
                    .error("Received a QUIC ACK frame but there is no QUIC packet layer");
            return;
        }
        packetLayer.handleAcknowledgement(object);
    }
}
