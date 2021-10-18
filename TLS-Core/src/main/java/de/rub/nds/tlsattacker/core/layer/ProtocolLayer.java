/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.core.layer;

import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public abstract class ProtocolLayer<T extends DataContainer> {

    private ProtocolLayer higherLayer = null;
    private ProtocolLayer lowerLayer = null;

    private LayerConfiguration layerConfiguration;

    private List<DataContainer> producedDataContainers;

    private boolean initialized = false;

    public ProtocolLayer getHigherLayer() {
        if (!initialized) {
            throw new RuntimeException("The ProtocolStack did not link the layers yet");
        }
        return higherLayer;
    }

    public ProtocolLayer getLowerLayer() {
        if (!initialized) {
            throw new RuntimeException("The ProtocolStack did not link the layers yet");
        }
        return lowerLayer;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    public void setHigherLayer(ProtocolLayer higherLayer) {
        this.higherLayer = higherLayer;
    }

    public void setLowerLayer(ProtocolLayer lowerLayer) {
        this.lowerLayer = lowerLayer;
    }

    public abstract LayerProcessingResult sendData(byte[] data);

    public abstract LayerProcessingResult receiveData();

    public LayerConfiguration getLayerConfiguration() {
        return layerConfiguration;
    }

    public void setLayerConfiguration(LayerConfiguration layerConfiguration) {
        this.layerConfiguration = layerConfiguration;
    }

    public List<DataContainer> getProducedDataContainers() {
        return producedDataContainers;
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
    }

}
