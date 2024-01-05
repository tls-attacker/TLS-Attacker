/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import static org.junit.Assert.*;

import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;

public class SpecificReceiveLayerConfigurationTest {

    public SpecificReceiveLayerConfigurationTest() {}

    @Test
    public void testExecutedAsPlanned() {
        List<ProtocolMessage> expectedMessages =
                Arrays.asList(
                        new ProtocolMessage[] {
                            new ServerHelloMessage(),
                            new CertificateMessage(),
                            new ECDHEServerKeyExchangeMessage(),
                            new ServerHelloDoneMessage()
                        });
        LayerConfiguration receiveConfig =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE, expectedMessages);
        assertTrue(receiveConfig.executedAsPlanned(expectedMessages));

        List<ProtocolMessage> missingLastMessage = new ArrayList(expectedMessages);
        missingLastMessage.remove(missingLastMessage.size() - 1);
        assertFalse(receiveConfig.executedAsPlanned(missingLastMessage));

        List<ProtocolMessage> missingMessageInbetween = new ArrayList(expectedMessages);
        missingMessageInbetween.remove(1);
        assertFalse(receiveConfig.executedAsPlanned(missingMessageInbetween));

        List<ProtocolMessage> missingFirstMessage = new ArrayList(expectedMessages);
        missingFirstMessage.remove(0);
        assertFalse(receiveConfig.executedAsPlanned(missingFirstMessage));

        List<ProtocolMessage> additionalLast = new ArrayList(expectedMessages);
        additionalLast.add(new ServerHelloDoneMessage());
        assertFalse(receiveConfig.executedAsPlanned(additionalLast));

        List<ProtocolMessage> additionalInbetween = new ArrayList(expectedMessages);
        additionalInbetween.add(1, new ServerHelloDoneMessage());
        assertFalse(receiveConfig.executedAsPlanned(additionalInbetween));
    }

    @Test
    public void testExecutedAsPlannedWithOptional() {
        ChangeCipherSpecMessage optionalChangeCipherSpec = new ChangeCipherSpecMessage();
        optionalChangeCipherSpec.setRequired(false);
        List<ProtocolMessage> expectedMessages =
                Arrays.asList(
                        new ProtocolMessage[] {
                            new ServerHelloMessage(),
                            optionalChangeCipherSpec,
                            new CertificateMessage(),
                            new CertificateVerifyMessage(),
                            new FinishedMessage()
                        });
        LayerConfiguration receiveConfig =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE, expectedMessages);
        assertTrue(receiveConfig.executedAsPlanned(expectedMessages));

        List<ProtocolMessage> missingOptional = new ArrayList(expectedMessages);
        missingOptional.remove(1);
        assertTrue(receiveConfig.executedAsPlanned(missingOptional));

        List<ProtocolMessage> missingLastMessage = new ArrayList(expectedMessages);
        missingLastMessage.remove(missingLastMessage.size() - 1);
        assertFalse(receiveConfig.executedAsPlanned(missingLastMessage));

        List<ProtocolMessage> missingMessageInbetween = new ArrayList(expectedMessages);
        missingMessageInbetween.remove(2);
        assertFalse(receiveConfig.executedAsPlanned(missingMessageInbetween));

        List<ProtocolMessage> missingFirstMessage = new ArrayList(expectedMessages);
        missingFirstMessage.remove(0);
        assertFalse(receiveConfig.executedAsPlanned(missingFirstMessage));

        List<ProtocolMessage> additionalLast = new ArrayList(expectedMessages);
        additionalLast.add(new ServerHelloDoneMessage());
        assertFalse(receiveConfig.executedAsPlanned(additionalLast));

        List<ProtocolMessage> additionalInbetween = new ArrayList(expectedMessages);
        additionalInbetween.add(1, new ServerHelloDoneMessage());
        assertFalse(receiveConfig.executedAsPlanned(additionalInbetween));
    }

    @Test
    public void testFailedEarly() {
        List<ProtocolMessage> expectedMessages =
                Arrays.asList(
                        new ProtocolMessage[] {
                            new ServerHelloMessage(),
                            new CertificateMessage(),
                            new ECDHEServerKeyExchangeMessage(),
                            new ServerHelloDoneMessage()
                        });
        LayerConfiguration receiveConfig =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE, expectedMessages);

        List<ProtocolMessage> buildingReceived = new LinkedList<>();
        for (ProtocolMessage message : expectedMessages) {
            buildingReceived.add(message);
            assertFalse(receiveConfig.failedEarly(buildingReceived));
        }

        List<ProtocolMessage> thirdInvalid =
                Arrays.asList(
                        new ProtocolMessage[] {
                            new ServerHelloMessage(),
                            new CertificateMessage(),
                            new CertificateVerifyMessage()
                        });
        assertTrue(receiveConfig.failedEarly(thirdInvalid));
    }
}
