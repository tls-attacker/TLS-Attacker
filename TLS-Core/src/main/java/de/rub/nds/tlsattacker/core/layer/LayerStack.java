/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Aggregates multiple layers into a protocol stack. Offers functionality for sending and receiving
 * messages through the message stack. Can be created manually or using {@link LayerStackFactory}.
 */
public class LayerStack {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The layer list, layer 0 is the highest layer, layer n is the lowest. Eg. For TLS layer 0
     * could be the application layer, layer 1 the tls message layer layer 2 the record layer and
     * layer 3 the tcp transport layer, layer 4 could be the ip layer layer 5 could be the ethernet
     * layer. Not all layers need to be defined at any time, it is perfectly fine to leave the layer
     * stack and plug another component in which does the rest of the processing
     */
    private final List<ProtocolLayer> layerList;

    private final Context context;

    public LayerStack(Context context, ProtocolLayer... layers) {
        this.context = context;
        layerList = Arrays.asList(layers);
        for (int i = 0; i < layers.length; i++) {
            ProtocolLayer layer = layerList.get(i);
            if (i != 0) {
                layer.setHigherLayer(layerList.get(i - 1));
            }
            if (i != layers.length - 1) {
                layer.setLowerLayer(layerList.get(i + 1));
            }
        }
    }

    public final ProtocolLayer getLayer(Class<? extends ProtocolLayer> layerClass) {
        for (ProtocolLayer layer : getLayerList()) {
            if (layer.getClass().equals(layerClass)) {
                return layer;
            }
        }
        return null;
    }

    public ProtocolLayer getHighestLayer() {
        return getLayerList().get(0);
    }

    public ProtocolLayer getLowestLayer() {
        return getLayerList().get(getLayerList().size() - 1);
    }

    /**
     * Sends data over the protocol stack based on the layer configurations provided in
     * layerConfigurationList.
     *
     * @param layerConfigurationList Contains {@link DataContainer} to be sent through the protocol
     *     stack.
     * @return LayerStackProcessingResult Contains information about the "send" execution. Does not
     *     contain any messages the peer sends back.
     * @throws IOException If any layer fails to send its data.
     */
    public LayerStackProcessingResult sendData(List<LayerConfiguration> layerConfigurationList)
            throws IOException {
        LOGGER.debug("Sending Data");
        if (getLayerList().size() != layerConfigurationList.size()) {
            throw new RuntimeException(
                    "Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explicit configuration is desired). Expected "
                            + getLayerList().size()
                            + " but found "
                            + layerConfigurationList.size());
        }

        // Prepare layer configuration and clear previous executions
        for (int i = 0; i < getLayerList().size(); i++) {
            ProtocolLayer layer = getLayerList().get(i);
            layer.clear();
            layer.setLayerConfiguration(layerConfigurationList.get(i));
        }
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        // Send data
        for (ProtocolLayer layer : getLayerList()) {
            layer.sendConfiguration();
        }

        // Gather results
        List<LayerProcessingResult> resultList = new LinkedList<>();
        getLayerList()
                .forEach(
                        layer -> {
                            resultList.add(layer.getLayerResult());
                        });
        return new LayerStackProcessingResult(resultList);
    }

    /**
     * Receives messages pre-defined in the layerConfigurationList through the message stack.
     * Timeouts if not all specified messages are received.
     *
     * @param layerConfigurationList Contains specific {@link DataContainer} to be received from the
     *     peer.
     * @return LayerStackProcessingResult Contains information about the "send" execution. Does not
     *     contain any messages the peer sends back. If any layer fails to receive the specified
     *     data.
     */
    public LayerStackProcessingResult receiveData(List<LayerConfiguration> layerConfigurationList) {
        LOGGER.debug("Receiving Data");
        if (getLayerList().size() != layerConfigurationList.size()) {
            throw new RuntimeException(
                    "Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explicit configuration is desired). Expected "
                            + getLayerList().size()
                            + " but found "
                            + layerConfigurationList.size());
        }
        // Prepare layer configuration and clear previous executions
        for (int i = 0; i < getLayerList().size(); i++) {
            ProtocolLayer layer = getLayerList().get(i);
            layer.clear();
            layer.setLayerConfiguration(layerConfigurationList.get(i));
        }
        context.setTalkingConnectionEndType(
                context.getConnection().getLocalConnectionEndType().getPeer());
        getLayerList().get(0).receiveData();
        // reverse order
        for (int i = getLayerList().size() - 1; i >= 0; i--) {
            ProtocolLayer layer = getLayerList().get(i);
            if (layer.getLayerConfiguration() != null && !layer.executedAsPlanned()) {
                try {
                    layer.receiveData();
                } catch (UnsupportedOperationException e) {
                    // most layers dont know how to receive data themselves
                    LOGGER.debug(
                            "Skipping layer "
                                    + layer.getLayerType()
                                    + ". Does not support direct data read.");
                }
            }
        }
        return gatherResults();
    }

    /**
     * Manually gathers information about each layer's execution. E.g., whether the layer executed
     * successfully and the peer's answers.
     *
     * @return LayerStackProcessingResult Contains the execution results of each layer.
     */
    public LayerStackProcessingResult gatherResults() {
        // Gather results
        List<LayerProcessingResult> resultList = new LinkedList<>();
        getLayerList().forEach(tempLayer -> resultList.add(tempLayer.getLayerResult()));
        return new LayerStackProcessingResult(resultList);
    }

    /** Returns the layers of this LayerStack by type. */
    public List<LayerType> getLayersInStack() {
        return layerList.stream().map(ProtocolLayer::getLayerType).collect(Collectors.toList());
    }

    /** Returns the layer list. */
    public List<ProtocolLayer> getLayerList() {
        return Collections.unmodifiableList(layerList);
    }
}
