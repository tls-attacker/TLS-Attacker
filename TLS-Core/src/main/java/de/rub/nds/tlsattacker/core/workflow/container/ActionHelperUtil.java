/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.container;

import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.GenericDataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.Tls.WarningAlertFilter;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
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

    public static List<DataContainer> getDataContainersForLayer(
            LayerType type, LayerStackProcessingResult processingResult) {
        if (processingResult == null) {
            return null;
        } else {
            for (LayerProcessingResult<?> result :
                    processingResult.getLayerProcessingResultList()) {
                if (result.getLayerType() == type) {
                    return (List<DataContainer>) result.getUsedContainers();
                }
            }
            return new LinkedList<>();
        }
    }

    public static List<LayerConfiguration<?>> sortAndAddOptions(
            LayerStack layerStack,
            boolean sending,
            Set<ActionOption> actionOptions,
            List<LayerConfiguration<?>> unsortedLayerConfigurations) {
        unsortedLayerConfigurations =
                sortLayerConfigurations(layerStack, sending, unsortedLayerConfigurations);
        return applyAllMessageFilters(unsortedLayerConfigurations, actionOptions);
    }

    public static List<LayerConfiguration<?>> applyAllMessageFilters(
            List<LayerConfiguration<?>> messageLayerConfiguration,
            Set<ActionOption> actionOptions) {
        for (LayerConfiguration<?> layerConfig : messageLayerConfiguration) {
            applyMessageFilters(layerConfig, actionOptions);
        }
        return messageLayerConfiguration;
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

    public static List<LayerConfiguration<?>> createReceiveTillHttpContentConfiguration(
            TlsContext tlsContext, String httpContent) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration httpConfiguration =
                new ReceiveTillHttpContentConfiguration(null, httpContent);

        SpecificReceiveLayerConfiguration messageConfiguration =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE);

        // allow for additional application data to arrive unhandled
        messageConfiguration.setAllowTrailingContainers(true);

        return ActionHelperUtil.sortLayerConfigurations(
                layerStack, false, List.of(httpConfiguration, messageConfiguration));
    }

    private static List<LayerConfiguration<?>> sortLayerConfigurations(
            LayerStack layerStack,
            boolean sending,
            List<LayerConfiguration<?>> unsortedLayerConfigurations) {
        List<LayerConfiguration<?>> sortedLayerConfigurations = new LinkedList<>();
        // iterate over all layers in the stack and assign the correct configuration
        // reset configurations to only assign a configuration to the upper most layer
        // Layer above configured layers will be set to ignore, layers below which are
        // not configured will be set to "does not matter"

        List<LayerConfiguration<?>> unsortedLayerConfigurationsMutable =
                new LinkedList<>(unsortedLayerConfigurations);
        boolean alreadyConfiguredLayer = false;
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
                    unsortedLayerConfigurationsMutable.stream()
                            .filter(Objects::nonNull)
                            .filter(layerConfig -> layerConfig.getLayerType().equals(layer))
                            .findFirst();

            if (layerConfiguration.isPresent()) {
                alreadyConfiguredLayer = true;
                sortedLayerConfigurations.add(layerConfiguration.get());
                unsortedLayerConfigurationsMutable.remove(layerConfiguration.get());
            } else {
                if (alreadyConfiguredLayer) {
                    if (sending) {
                        sortedLayerConfigurations.add(
                                new MissingSendLayerConfiguration<>(layerType));
                    } else {
                        sortedLayerConfigurations.add(
                                new MissingReceiveLayerConfiguration<>(layerType));
                    }
                } else {
                    sortedLayerConfigurations.add(new IgnoreLayerConfiguration<>(layerType));
                }
            }
        }
        return sortedLayerConfigurations;
    }
}
