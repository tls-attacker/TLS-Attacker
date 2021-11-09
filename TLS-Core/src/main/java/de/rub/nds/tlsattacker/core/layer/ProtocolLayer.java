/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public abstract class ProtocolLayer<Hint extends LayerProcessingHint, Container extends DataContainer> {

    private ProtocolLayer higherLayer = null;
    private ProtocolLayer lowerLayer = null;

    private LayerConfiguration<Container> layerConfiguration;

    private List<Container> producedDataContainers;

    private boolean initialized = false;

    private ByteArrayOutputStream resultDataStream;

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

    public abstract LayerProcessingResult sendData() throws IOException;

    public abstract LayerProcessingResult sendData(byte[] data) throws IOException;

    public abstract LayerProcessingResult sendData(Hint hint) throws IOException;

    public abstract LayerProcessingResult sendData(Hint hint, byte[] additionalData) throws IOException;

    protected ByteArrayOutputStream getResultDataStream() {
        return resultDataStream;
    }

    public LayerConfiguration<Container> getLayerConfiguration() {
        return layerConfiguration;
    }

    public void setLayerConfiguration(LayerConfiguration layerConfiguration) {
        this.layerConfiguration = layerConfiguration;
    }

    public LayerProcessingResult<Container> getLayerResult() {
        return new LayerProcessingResult(producedDataContainers, resultDataStream.toByteArray());
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
    }

    protected void addProducedContainer(Container container) {
        producedDataContainers.add(container);
    }

    public abstract byte[] retrieveMoreData(LayerProcessingHint hint) throws IOException;

    public abstract HintedLayerStream getDataStream();

}
