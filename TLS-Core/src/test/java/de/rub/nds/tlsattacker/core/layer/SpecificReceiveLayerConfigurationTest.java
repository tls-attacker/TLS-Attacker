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

import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration.ExecutionStatus;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
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

    private static class SpecificReceiveLayerConfigurationWithPublicEvaluate<
                    Container extends DataContainer>
            extends SpecificReceiveLayerConfiguration<Container> {
        public SpecificReceiveLayerConfigurationWithPublicEvaluate(
                ImplementedLayers layerType, List<Container> containerList) {
            super(layerType, containerList);
        }

        @Override
        public ExecutionStatus evaluateReceivedContainers(List<Container> list) {
            return super.evaluateReceivedContainers(list);
        }
    }

    @Test
    public void testEvaluateReceivedContainers() {
        List<ProtocolMessage> expectedMessages =
                Arrays.asList(
                        new ProtocolMessage[] {
                            new ServerHelloMessage(),
                            new CertificateMessage(),
                            new ECDHEServerKeyExchangeMessage(),
                            new ServerHelloDoneMessage()
                        });
        var receiveConfig =
                new SpecificReceiveLayerConfigurationWithPublicEvaluate<>(
                        ImplementedLayers.MESSAGE, expectedMessages);
        assertEquals(
                ExecutionStatus.AS_PLANNED,
                receiveConfig.evaluateReceivedContainers(expectedMessages));

        List<ProtocolMessage> missingLastMessage = new ArrayList<>(expectedMessages);
        missingLastMessage.remove(missingLastMessage.size() - 1);
        assertEquals(
                ExecutionStatus.PENDING_MISSING_CONTAINERS,
                receiveConfig.evaluateReceivedContainers(missingLastMessage));

        List<ProtocolMessage> missingMessageInbetween = new ArrayList<>(expectedMessages);
        missingMessageInbetween.remove(1);
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(missingMessageInbetween));

        List<ProtocolMessage> missingFirstMessage = new ArrayList<>(expectedMessages);
        missingFirstMessage.remove(0);
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(missingFirstMessage));

        List<ProtocolMessage> additionalLast = new ArrayList<>(expectedMessages);
        additionalLast.add(new ServerHelloDoneMessage());
        assertEquals(
                ExecutionStatus.ADDITIONAL_CONTAINERS,
                receiveConfig.evaluateReceivedContainers(additionalLast));

        List<ProtocolMessage> additionalInbetween = new ArrayList<>(expectedMessages);
        additionalInbetween.add(1, new ServerHelloDoneMessage());
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(additionalInbetween));
    }

    @Test
    public void testEvaluateReceivedContainersWithOptional() {
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
        var receiveConfig =
                new SpecificReceiveLayerConfigurationWithPublicEvaluate<>(
                        ImplementedLayers.MESSAGE, expectedMessages);
        assertEquals(
                ExecutionStatus.AS_PLANNED,
                receiveConfig.evaluateReceivedContainers(expectedMessages));

        List<ProtocolMessage> missingOptional = new ArrayList<>(expectedMessages);
        missingOptional.remove(1);
        assertEquals(
                ExecutionStatus.AS_PLANNED,
                receiveConfig.evaluateReceivedContainers(missingOptional));

        List<ProtocolMessage> missingLastMessage = new ArrayList<>(expectedMessages);
        missingLastMessage.remove(missingLastMessage.size() - 1);
        assertEquals(
                ExecutionStatus.PENDING_MISSING_CONTAINERS,
                receiveConfig.evaluateReceivedContainers(missingLastMessage));

        List<ProtocolMessage> missingMessageInbetween = new ArrayList<>(expectedMessages);
        missingMessageInbetween.remove(2);
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(missingMessageInbetween));

        List<ProtocolMessage> missingFirstMessage = new ArrayList<>(expectedMessages);
        missingFirstMessage.remove(0);
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(missingFirstMessage));

        List<ProtocolMessage> additionalLast = new ArrayList<>(expectedMessages);
        additionalLast.add(new ServerHelloDoneMessage());
        assertEquals(
                ExecutionStatus.ADDITIONAL_CONTAINERS,
                receiveConfig.evaluateReceivedContainers(additionalLast));

        List<ProtocolMessage> additionalInbetween = new ArrayList<>(expectedMessages);
        additionalInbetween.add(1, new ServerHelloDoneMessage());
        assertEquals(
                ExecutionStatus.UNEXPECTED_CONTAINER,
                receiveConfig.evaluateReceivedContainers(additionalInbetween));
    }

    private static boolean originalEvaluateReceivedContainers(
            SpecificReceiveLayerConfiguration self,
            List<? extends DataContainer> list,
            boolean mayReceiveMoreContainers) {
        if (list == null) {
            return false;
        }
        int j = 0;
        List<DataContainer> expectedContainers = self.getContainerList();
        if (expectedContainers != null) {
            for (int i = 0; i < expectedContainers.size(); i++) {
                if (j >= list.size() && expectedContainers.get(i).isRequired()) {
                    return mayReceiveMoreContainers;
                } else if (j < list.size()) {
                    if (!expectedContainers.get(i).getClass().equals(list.get(j).getClass())
                            && expectedContainers.get(i).isRequired()) {
                        if (self.containerCanBeFiltered(list.get(j))) {
                            j++;
                            i--;
                        } else {
                            return false;
                        }

                    } else if (expectedContainers
                            .get(i)
                            .getClass()
                            .equals(list.get(j).getClass())) {
                        j++;
                    }
                }
            }

            for (; j < list.size(); j++) {
                if (!self.containerCanBeFiltered(list.get(j)) && !mayReceiveMoreContainers) {
                    return false;
                }
            }
        }
        return true;
    }

    @Test
    public void testEvaluateReceivedContainersMigration() throws Exception {
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
        var receiveConfig =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE, expectedMessages);

        var newFunc =
                SpecificReceiveLayerConfiguration.class.getDeclaredMethod(
                        "evaluateReceivedContainers", List.class, boolean.class);
        newFunc.setAccessible(true);
        var newFuncDetails =
                SpecificReceiveLayerConfiguration.class.getDeclaredMethod(
                        "evaluateReceivedContainers", List.class);
        newFuncDetails.setAccessible(true);

        Function<List<ProtocolMessage>, Void> testFunc =
                (list) -> {
                    try {
                        assertEquals(
                                "New function return value differs, determined status "
                                        + newFuncDetails.invoke(receiveConfig, list)
                                        + " mayReceiveMoreContainers=false",
                                originalEvaluateReceivedContainers(receiveConfig, list, false),
                                newFunc.invoke(receiveConfig, list, false));
                        assertEquals(
                                "New function return value differs, determined status "
                                        + newFuncDetails.invoke(receiveConfig, list)
                                        + " mayReceiveMoreContainers=true",
                                originalEvaluateReceivedContainers(receiveConfig, list, true),
                                newFunc.invoke(receiveConfig, list, true));
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException(e);
                    } catch (InvocationTargetException e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                };

        testFunc.apply(expectedMessages);

        List<ProtocolMessage> missingOptional = new ArrayList(expectedMessages);
        missingOptional.remove(1);
        testFunc.apply(missingOptional);

        List<ProtocolMessage> missingLastMessage = new ArrayList(expectedMessages);
        missingLastMessage.remove(missingLastMessage.size() - 1);
        testFunc.apply(missingLastMessage);

        List<ProtocolMessage> missingMessageInbetween = new ArrayList(expectedMessages);
        missingMessageInbetween.remove(2);
        testFunc.apply(missingMessageInbetween);

        List<ProtocolMessage> missingFirstMessage = new ArrayList(expectedMessages);
        missingFirstMessage.remove(0);
        testFunc.apply(missingFirstMessage);

        List<ProtocolMessage> additionalLast = new ArrayList(expectedMessages);
        additionalLast.add(new ServerHelloDoneMessage());
        testFunc.apply(additionalLast);

        List<ProtocolMessage> additionalInbetween = new ArrayList(expectedMessages);
        additionalInbetween.add(1, new ServerHelloDoneMessage());
        testFunc.apply(additionalInbetween);
    }
}
