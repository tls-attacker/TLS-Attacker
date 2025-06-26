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

    @Test
    public void testMessageLayerReadsCompleteResultingMessage() {
        // This test verifies that MessageLayer reads the completeResultingMessage value
        // from the message and uses it during processing, not just writes to it

        // Create a test message with a specific completeResultingMessage
        byte[] expectedMessageContent = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
        ClientHelloMessage message = new ClientHelloMessage();
        message.setAdjustContext(false);
        message.setCompleteResultingMessage(Modifiable.explicit(expectedMessageContent));

        // Send the message
        SendAction sendAction = new SendAction("client", message);
        sendAction.execute(state);

        // The expected output should include:
        // - Record header: type (0x16 for handshake), version (3,3), length (0,5)
        // - The message content from completeResultingMessage
        byte[] expectedOutput =
                new byte[] {
                    0x16, // Handshake type
                    0x03,
                    0x03, // TLS 1.2 version
                    0x00,
                    0x05, // Length of content (5 bytes)
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05 // The actual message content
                };

        // Verify that the sent bytes include the content from completeResultingMessage
        Assert.assertArrayEquals(expectedOutput, transportHandler.getSentBytes());
    }

    @Test
    public void testMultipleMessagesReadCompleteResultingMessage() {
        // Test that when multiple handshake messages are sent,
        // MessageLayer reads each one's completeResultingMessage

        byte[] message1Content = new byte[] {0x01, 0x02};
        byte[] message2Content = new byte[] {0x03, 0x04, 0x05};

        ClientHelloMessage message1 = new ClientHelloMessage();
        message1.setAdjustContext(false);
        message1.setCompleteResultingMessage(Modifiable.explicit(message1Content));

        ClientHelloMessage message2 = new ClientHelloMessage();
        message2.setAdjustContext(false);
        message2.setCompleteResultingMessage(Modifiable.explicit(message2Content));

        // Send both messages in one action
        SendAction sendAction = new SendAction("client", message1, message2);
        sendAction.execute(state);

        // When messages have completeResultingMessage already set,
        // they are sent in separate records
        byte[] expectedOutput =
                new byte[] {
                    // First record with message1
                    0x16, // Handshake type
                    0x03,
                    0x03, // TLS 1.2 version
                    0x00,
                    0x02, // Length of content (2 bytes)
                    0x01,
                    0x02, // message1 content
                    // Second record with message2
                    0x16, // Handshake type
                    0x03,
                    0x03, // TLS 1.2 version
                    0x00,
                    0x03, // Length of content (3 bytes)
                    0x03,
                    0x04,
                    0x05 // message2 content
                };

        Assert.assertArrayEquals(expectedOutput, transportHandler.getSentBytes());
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
