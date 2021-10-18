package de.rub.nds.tlsattacker.core.layer;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LayerStack {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The layer list, layer 0 is the highest layer, layer n is the lowest. Eg.
     * For TLS layer 0 could be the application layer, layer 1 the tls message
     * layer layer 2 the record layer and layer 3 the tcp transport layer, layer
     * 4 could be the ip layer layer 5 could be the ethernet layer. Not all
     * layers need to be defined at any time, it is perfectly fine to leave the
     * layer stack and plug another component in which does the rest of the
     * processing
     */
    private final List<ProtocolLayer> layerList;

    public LayerStack(ProtocolLayer... layers) {
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

    public List<LayerProcessingResult> sendData(List<LayerConfiguration> layerConfigurationList) {
        int i = 0;
        for (ProtocolLayer layer : layerList) {
            layer.clear();
            layer.setLayerConfiguration(layerConfigurationList.get(i));
            i++;
        }
    }

    public List<LayerProcessingResult> sendLayerConfigurations(List<LayerConfiguration> layerConfigurationList) {
        if (layerList.size() != layerConfigurationList.size()) {
            throw new RuntimeException("Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explict configuration is desired). Expected " + layerList.size() + " but found " + layerConfigurationList.size());
        }
        List<LayerProcessingResult> resultList = new LinkedList<>();
        byte[] lowerLayerData = null;
        //traverse layers in order
        for (int i = 0; i < layerList.size(); i++) {
            LayerConfiguration configuration = layerConfigurationList.get(i);
            if (configuration == null) {
                continue;
            }
            if (lowerLayerData != null) {
                if (configuration.getAdditionalLayerData() == null) {
                    LOGGER.warn("Layer is configured to use additionalData but higher layer provided data. Overwriting configuration!");
                }
                configuration.setAdditionalLayerData(lowerLayerData);
            }
            LayerProcessingResult result = layerList.get(i).sendConfiguration(configuration);
            lowerLayerData = result.getResultingData();
            resultList.add(result);
        }
        return resultList;
    }

    public List<LayerProcessingResult> receiveLayerConfigurations(List<LayerConfiguration> layerConfigurationList) {
        if (layerList.size() != layerConfigurationList.size()) {
            throw new RuntimeException("Illegal LayerConfiguration list provided. Each layer needs a configuration entry (null is fine too if no explict configuration is desired). Expected " + layerList.size() + " but found " + layerConfigurationList.size());
        }
        List<LayerProcessingResult> resultList = new LinkedList<>();
        byte[] higherLayerData = null;
        //Traverse layers in the reverse order
        for (int i = layerList.size() - 1; i >= 0; i--) {
            LayerConfiguration configuration = layerConfigurationList.get(i);
            if (configuration == null) {
                continue;
            }
            if (higherLayerData != null) {
                if (configuration.getAdditionalLayerData() == null) {
                    LOGGER.warn("Layer is configured to use additionalData but higher layer provided data. Overwriting configuration!");
                }
                configuration.setAdditionalLayerData(higherLayerData);
            }
            LayerProcessingResult result = layerList.get(i).receiveData();
            higherLayerData = result.getResultingData();
            resultList.add(result);
        }
        return resultList;
    }
}
