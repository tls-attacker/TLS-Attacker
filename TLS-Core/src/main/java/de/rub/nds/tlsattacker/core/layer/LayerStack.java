/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class LayerStack {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The layer list, layer 0 is the highest layer, layer n is the lowest. Eg. For TLS layer 0 could be the application
     * layer, layer 1 the tls message layer layer 2 the record layer and layer 3 the tcp transport layer, layer 4 could
     * be the ip layer layer 5 could be the ethernet layer. Not all layers need to be defined at any time, it is
     * perfectly fine to leave the layer stack and plug another component in which does the rest of the processing
     */
    private final List<ProtocolLayer> layerList;
    // TODO This should be a context, not a TLS context
    private final TlsContext context;

    public LayerStack(TlsContext context, ProtocolLayer... layers) {
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
        for (ProtocolLayer layer : layerList) {
            if (layer.getClass().equals(layerClass)) {
                return layer;
            }
        }
        return null;
    }

    public ProtocolLayer getHighestLayer() {
        return layerList.get(0);
    }

    public ProtocolLayer getLowestLayer() {
        return layerList.get(layerList.size() - 1);
    }

    public List<LayerProcessingResult> sendData(List<LayerConfiguration> layerConfigurationList) throws IOException {
        LOGGER.debug("Sending Data");
        if (layerList.size() != layerConfigurationList.size()) {
            throw new RuntimeException(
                "Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explict configuration is desired). Expected "
                    + layerList.size() + " but found " + layerConfigurationList.size());
        }

        // Prepare layer configuration and clear previous executions
        for (int i = 0; i < layerList.size(); i++) {
            ProtocolLayer layer = layerList.get(i);
            layer.clear();
            layer.setLayerConfiguration(layerConfigurationList.get(i));
            i++;
        }
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        // Send data
        for (ProtocolLayer layer : layerList) {
            layer.sendConfiguration();
        }

        // Gather results
        List<LayerProcessingResult> resultList = new LinkedList<>();
        layerList.forEach(layer -> {
            resultList.add(layer.getLayerResult());
        });
        return resultList;
    }

    public List<LayerProcessingResult> receiveData(List<LayerConfiguration> layerConfigurationList) throws IOException {
        LOGGER.debug("Receiving Data");
        if (layerList.size() != layerConfigurationList.size()) {
            throw new RuntimeException(
                "Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explict configuration is desired). Expected "
                    + layerList.size() + " but found " + layerConfigurationList.size());
        }
        // Prepare layer configuration and clear previous executions
        for (int i = 0; i < layerList.size(); i++) {
            ProtocolLayer layer = layerList.get(i);
            layer.clear();
            layer.setLayerConfiguration(layerConfigurationList.get(i));
        }
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType().getPeer());
        layerList.get(0).receiveData();
        // reverse order
        for (int i = layerList.size() - 1; i <= 0; i--) {
            ProtocolLayer layer = layerList.get(i);
            if (layer.getLayerConfiguration() != null && !layer.executedAsPlanned()) {
                layer.receiveData();
            }
        }
        return gatherResults();
    }

    public List<LayerProcessingResult> gatherResults() {
        // Gather results
        List<LayerProcessingResult> resultList = new LinkedList<>();
        layerList.forEach(tempLayer -> {
            resultList.add(tempLayer.getLayerResult());
        });
        return resultList;
    }
}
