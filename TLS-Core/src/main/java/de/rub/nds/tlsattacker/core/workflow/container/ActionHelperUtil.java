/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.container;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.ReceiveTillLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.TightReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.GenericDataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.Tls.WarningAlertFilter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ActionHelperUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    private ActionHelperUtil() {}

    public static List<DataContainer<?>> getDataContainersForLayer(
            LayerType type, LayerStackProcessingResult processingResult) {
        if (processingResult == null) {
            return null;
        } else {
            for (LayerProcessingResult<?> result :
                    processingResult.getLayerProcessingResultList()) {
                if (result.getLayerType() == type) {
                    return (List<DataContainer<?>>) result.getUsedContainers();
                }
            }
            return new LinkedList<>();
        }
    }

    public static List<LayerConfiguration> createReceivLayerConfiguration(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToReceive,
            List<DtlsHandshakeMessageFragment> fragmentsToReceive,
            List<Record> recordsToReceive,
            List<QuicFrame> framesToReceive,
            List<QuicPacket> packetsToReceive,
            List<HttpMessage> httpMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList;
        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        createReceiveConfiguration(
                                ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive),
                        createReceiveConfiguration(
                                ImplementedLayers.MESSAGE, protocolMessagesToReceive),
                        createReceiveConfiguration(
                                ImplementedLayers.SSL2, protocolMessagesToReceive),
                        createReceiveConfiguration(ImplementedLayers.RECORD, recordsToReceive),
                        createReceiveConfiguration(ImplementedLayers.HTTP, httpMessagesToReceive),
                        createReceiveConfiguration(ImplementedLayers.QUICFRAME, framesToReceive),
                        createReceiveConfiguration(ImplementedLayers.QUICPACKET, packetsToReceive));
        return layerConfigurationList;
    }

    public static ReceiveLayerConfiguration createReceiveConfiguration(
            LayerType layerType, List<? extends DataContainer<?>> containersToReceive) {
        if (containersToReceive == null || containersToReceive.isEmpty()) {
            return new GenericReceiveLayerConfiguration(layerType);
        } else {
            if (layerType == ImplementedLayers.MESSAGE) {
                return (ReceiveLayerConfiguration)
                        ActionHelperUtil.applyMessageFilters(
                                new SpecificReceiveLayerConfiguration<>(
                                        layerType, containersToReceive));
            }
            return new SpecificReceiveLayerConfiguration<>(layerType, containersToReceive);
        }
    }

    public static List<LayerConfiguration> createReceiveTillConfiguration(
            TlsContext tlsContext, List<QuicFrame> quicFrame, List<QuicPacket> quicPacket) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new ReceiveTillLayerConfiguration(ImplementedLayers.QUICFRAME, quicFrame);

        return ActionHelperUtil.sortLayerConfigurations(layerStack, messageConfiguration);
    }

    public static List<LayerConfiguration> createReceiveTillConfiguration(
            TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new ReceiveTillLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessageToReceive);

        return ActionHelperUtil.sortLayerConfigurations(layerStack, messageConfiguration);
    }

    public static List<LayerConfiguration> createTightReceiveConfiguration(
            TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new TightReceiveLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(layerStack, messageConfiguration);
        return layerConfigurationList;
    }

    public static List<LayerConfiguration> createSendConfiguration(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToSend,
            List<DtlsHandshakeMessageFragment> fragmentsToSend,
            List<Record> recordsToSend,
            List<QuicFrame> framesToSend,
            List<QuicPacket> packetsToSend,
            List<HttpMessage> httpMessagesToSend) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration dtlsConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.DTLS_FRAGMENT, fragmentsToSend);
        LayerConfiguration messageConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.MESSAGE, protocolMessagesToSend);
        LayerConfiguration ssl2Configuration =
                new SpecificSendLayerConfiguration(ImplementedLayers.SSL2, protocolMessagesToSend);
        LayerConfiguration recordConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, recordsToSend);
        LayerConfiguration httpConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.HTTP, httpMessagesToSend);
        LayerConfiguration quicFrameConfiguration =
                new SpecificSendLayerConfiguration(ImplementedLayers.QUICFRAME, framesToSend);
        LayerConfiguration quicPacketConfiguration =
                new SpecificSendLayerConfiguration(ImplementedLayers.QUICPACKET, packetsToSend);

        checkLayerConsistency(layerStack, httpMessagesToSend);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        dtlsConfiguration,
                        messageConfiguration,
                        recordConfiguration,
                        ssl2Configuration,
                        quicFrameConfiguration,
                        quicPacketConfiguration,
                        httpConfiguration);
        return layerConfigurationList;
    }

    public static LayerConfiguration applyMessageFilters(
            LayerConfiguration messageLayerConfiguration, Set<ActionOption> actionOptions) {
        List<DataContainerFilter> containerFilters = new LinkedList<>();
        if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_APP_DATA)) {
            containerFilters.add(new GenericDataContainerFilter(ApplicationMessage.class));
        }
        if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES)) {
            containerFilters.add(new GenericDataContainerFilter(KeyUpdateMessage.class));
        }
        if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS)) {
            containerFilters.add(new GenericDataContainerFilter(NewSessionTicketMessage.class));
        }
        if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS)) {
            containerFilters.add(new WarningAlertFilter());
        }
        if (messageLayerConfiguration instanceof SpecificReceiveLayerConfiguration) {
            ((SpecificReceiveLayerConfiguration) messageLayerConfiguration)
                    .setContainerFilterList(containerFilters);
        }
        return messageLayerConfiguration;
    }

    public static List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, LayerConfiguration... unsortedLayerConfigurations) {
        return sortLayerConfigurations(
                layerStack, new LinkedList<>(Arrays.asList(unsortedLayerConfigurations)));
    }

    public static List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, List<LayerConfiguration> unsortedLayerConfigurations) {
        List<LayerConfiguration> sortedLayerConfigurations = new LinkedList<>();
        // iterate over all layers in the stack and assign the correct configuration
        // reset configurations to only assign a configuration to the upper most layer
        for (LayerType layerType : layerStack.getLayersInStack()) {
            ImplementedLayers layer;
            try {
                layer = (ImplementedLayers) layerType;
            } catch (ClassCastException e) {
                LOGGER.warn(
                        "Cannot assign layer "
                                + layerType.getName()
                                + "to current LayerStack. LayerType not implemented for TLSAction.");
                continue;
            }
            Optional<LayerConfiguration> layerConfiguration = Optional.empty();
            if (layer == ImplementedLayers.MESSAGE
                    || layer == ImplementedLayers.RECORD
                    || layer == ImplementedLayers.DTLS_FRAGMENT
                    || layer == ImplementedLayers.HTTP
                    || layer == ImplementedLayers.SSL2
                    || layer == ImplementedLayers.QUICFRAME
                    || layer == ImplementedLayers.QUICPACKET) {
                layerConfiguration =
                        unsortedLayerConfigurations.stream()
                                .filter(Objects::nonNull)
                                .filter(layerConfig -> layerConfig.getLayerType().equals(layer))
                                .findFirst();
            }
            if (layerConfiguration.isPresent()) {
                sortedLayerConfigurations.add(layerConfiguration.get());
                unsortedLayerConfigurations.remove(layerConfiguration.get());
            } else {
                sortedLayerConfigurations.add(
                        new SpecificReceiveLayerConfiguration(layerType, new LinkedList<>()));
            }
        }
        return sortedLayerConfigurations;
    }
}
