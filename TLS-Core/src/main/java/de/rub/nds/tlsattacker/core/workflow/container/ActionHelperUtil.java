/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.container;

import de.rub.nds.tlsattacker.core.dtls.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.MissingReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.MissingSendLayerConfiguration;
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

    public static List<LayerConfiguration<?>> createReceiveLayerConfiguration(
            TlsContext tlsContext,
            Set<ActionOption> actionOptions,
            List<ProtocolMessage> protocolMessagesToReceive,
            List<DtlsHandshakeMessageFragment> fragmentsToReceive,
            List<Record> recordsToReceive,
            List<QuicFrame> framesToReceive,
            List<QuicPacket> packetsToReceive,
            List<HttpMessage> httpMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration<?>> layerConfigurationList;
        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        false,
                        createReceiveConfiguration(
                                ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive, actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.MESSAGE,
                                protocolMessagesToReceive,
                                actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.SSL2, protocolMessagesToReceive, actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.RECORD, recordsToReceive, actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.HTTP, httpMessagesToReceive, actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.QUICFRAME, framesToReceive, actionOptions),
                        createReceiveConfiguration(
                                ImplementedLayers.QUICPACKET, packetsToReceive, actionOptions));
        return layerConfigurationList;
    }

    public static ReceiveLayerConfiguration<?> createReceiveConfiguration(
            LayerType layerType,
            List<? extends DataContainer<?>> containersToReceive,
            Set<ActionOption> actionOptions) {
        if (containersToReceive == null) {
            return new MissingReceiveLayerConfiguration(layerType);

        } else if (containersToReceive.isEmpty()) {
            return new GenericReceiveLayerConfiguration(layerType);
        } else {
            if (layerType == ImplementedLayers.MESSAGE) {
                return (ReceiveLayerConfiguration<?>)
                        ActionHelperUtil.applyMessageFilters(
                                new SpecificReceiveLayerConfiguration<>(
                                        layerType, containersToReceive),
                                actionOptions);
            }
            return new SpecificReceiveLayerConfiguration<>(layerType, containersToReceive);
        }
    }

    public static List<LayerConfiguration<?>> createReceiveTillConfiguration(
            TlsContext tlsContext, List<QuicFrame> quicFrame, List<QuicPacket> quicPacket) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration<?> messageConfiguration =
                new ReceiveTillLayerConfiguration<QuicFrame>(
                        ImplementedLayers.QUICFRAME, quicFrame);

        return ActionHelperUtil.sortLayerConfigurations(layerStack, false, messageConfiguration);
    }

    public static List<LayerConfiguration<?>> createReceiveTillConfiguration(
            TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration<?> messageConfiguration =
                new ReceiveTillLayerConfiguration<ProtocolMessage>(
                        ImplementedLayers.MESSAGE, protocolMessageToReceive);

        return ActionHelperUtil.sortLayerConfigurations(layerStack, false, messageConfiguration);
    }

    public static List<LayerConfiguration<?>> createTightReceiveConfiguration(
            TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration<?> messageConfiguration =
                new TightReceiveLayerConfiguration<ProtocolMessage>(
                        ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration<?>> layerConfigurationList =
                sortLayerConfigurations(layerStack, false, messageConfiguration);
        return layerConfigurationList;
    }

    public static List<LayerConfiguration<?>> createSendConfiguration(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToSend,
            List<DtlsHandshakeMessageFragment> fragmentsToSend,
            List<Record> recordsToSend,
            List<QuicFrame> framesToSend,
            List<QuicPacket> packetsToSend,
            List<HttpMessage> httpMessagesToSend) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration<?>> layerConfigurationsList = new LinkedList<>();

        if (fragmentsToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.DTLS_FRAGMENT, fragmentsToSend));
        }

        if (protocolMessagesToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, protocolMessagesToSend));
        }

        // TODO SSL2 missing here
        if (recordsToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, recordsToSend));
        }
        if (httpMessagesToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.HTTP, httpMessagesToSend));
        }
        if (framesToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICFRAME, framesToSend));
        }
        if (packetsToSend != null) {
            layerConfigurationsList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICPACKET, packetsToSend));
        }

        layerConfigurationsList =
                sortLayerConfigurations(layerStack, true, layerConfigurationsList);
        return layerConfigurationsList;
    }

    public static LayerConfiguration<?> applyMessageFilters(
            LayerConfiguration<?> messageLayerConfiguration, Set<ActionOption> actionOptions) {
        List<DataContainerFilter> containerFilters = new LinkedList<>();
        if (actionOptions != null) {
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
                ((SpecificReceiveLayerConfiguration<?>) messageLayerConfiguration)
                        .setContainerFilterList(containerFilters);
            }
        }
        return messageLayerConfiguration;
    }

    public static List<LayerConfiguration<?>> sortLayerConfigurations(
            LayerStack layerStack,
            boolean sending,
            LayerConfiguration<?>... unsortedLayerConfigurations) {
        return sortLayerConfigurations(
                layerStack, sending, new LinkedList<>(Arrays.asList(unsortedLayerConfigurations)));
    }

    public static List<LayerConfiguration<?>> sortLayerConfigurations(
            LayerStack layerStack,
            boolean sending,
            List<LayerConfiguration<?>> unsortedLayerConfigurations) {
        List<LayerConfiguration<?>> sortedLayerConfigurations = new LinkedList<>();
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
            Optional<LayerConfiguration<?>> layerConfiguration = Optional.empty();

            layerConfiguration =
                    unsortedLayerConfigurations.stream()
                            .filter(Objects::nonNull)
                            .filter(layerConfig -> layerConfig.getLayerType().equals(layer))
                            .findFirst();

            if (layerConfiguration.isPresent()) {
                sortedLayerConfigurations.add(layerConfiguration.get());
                unsortedLayerConfigurations.remove(layerConfiguration.get());
            } else {
                if (sending) {
                    sortedLayerConfigurations.add(new MissingSendLayerConfiguration<>(layerType));
                } else {
                    sortedLayerConfigurations.add(
                            new MissingReceiveLayerConfiguration<>(layerType));
                }
            }
        }
        return sortedLayerConfigurations;
    }
}
