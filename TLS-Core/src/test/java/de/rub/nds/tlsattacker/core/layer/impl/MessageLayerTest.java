/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.HashSet;
import java.util.Set;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

public class MessageLayerTest extends AbstractLayerTest {

    @Test
    public void testSendEmptyMessage() {
        Set<ProtocolMessageType> typesToTest = new HashSet<>();
        typesToTest.add(ProtocolMessageType.HANDSHAKE);
        typesToTest.add(ProtocolMessageType.HEARTBEAT);
        typesToTest.add(ProtocolMessageType.APPLICATION_DATA);
        typesToTest.add(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        typesToTest.add(ProtocolMessageType.ALERT);
        for (ProtocolMessageType type : typesToTest) {
            ProtocolMessage message = createProtocolMessage(type);
            SendAction sendEmptyMessage = new SendAction("client", message);
            sendEmptyMessage.execute(state);
            byte[] recordHeaderOnly = new byte[] {type.getValue(), 3, 3, 0, 0};
            Assert.assertArrayEquals(recordHeaderOnly, transportHandler.getSentBytes());
            transportHandler.resetOutputStream();
        }
    }

    private ProtocolMessage createProtocolMessage(ProtocolMessageType protocolMessageType) {
        ProtocolMessage message = null;
        switch (protocolMessageType) {
            case HANDSHAKE:
                message = new ClientHelloMessage();
                break;
            case HEARTBEAT:
                message = new HeartbeatMessage();
                break;
            case APPLICATION_DATA:
                message = new ApplicationMessage();
                break;
            case CHANGE_CIPHER_SPEC:
                message = new ChangeCipherSpecMessage();
                break;
            case ALERT:
                message = new AlertMessage();
                break;
            default:
                throw new IllegalArgumentException(
                        "Unexpected message type: " + protocolMessageType);
        }
        message.setAdjustContext(false);
        message.setCompleteResultingMessage(Modifiable.explicit(new byte[0]));
        return message;
    }
}
