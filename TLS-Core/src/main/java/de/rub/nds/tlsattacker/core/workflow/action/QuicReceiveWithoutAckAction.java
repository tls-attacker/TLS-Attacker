/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.impl.QuicPacketLayer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name = "QuicReceiveWithoutAck")
public class QuicReceiveWithoutAckAction extends ReceiveAction {

    public QuicReceiveWithoutAckAction() {
        super();
    }

    public QuicReceiveWithoutAckAction(List<ProtocolMessage> expectedMessages) {
        super(expectedMessages);
    }

    public QuicReceiveWithoutAckAction(ProtocolMessage... expectedMessages) {
        super(expectedMessages);
    }

    public QuicReceiveWithoutAckAction(QuicPacket... expectedQuicPackets) {
        super(expectedQuicPackets);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        QuicPacketLayer layer =
                (QuicPacketLayer)
                        state.getContext().getLayerStack().getLayer(QuicPacketLayer.class);
        if (layer != null) {
            layer.setTemporarilyDisabledAcks(true);
        }
        super.execute(state);
        if (layer != null) {
            layer.setTemporarilyDisabledAcks(false);
        }
    }
}
