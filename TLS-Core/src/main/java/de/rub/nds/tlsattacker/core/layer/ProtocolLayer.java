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
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.protocol.Handler;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public abstract class ProtocolLayer<Hint extends LayerProcessingHint, Container extends DataContainer> {

    private ProtocolLayer higherLayer = null;
    private ProtocolLayer lowerLayer = null;

    private LayerConfiguration<Container> layerConfiguration;

    private List<Container> producedDataContainers;

    private ByteArrayOutputStream unprocessedData;

    protected HintedInputStream currentInputStream = null;

    protected HintedInputStream nextInputStream = null;

    public ProtocolLayer() {
        unprocessedData = new ByteArrayOutputStream();
        producedDataContainers = new LinkedList<>();
    }

    public ByteArrayOutputStream getUnprocessedDataStream() {
        return unprocessedData;
    }

    public void setUnprocessedData(ByteArrayOutputStream unprocessedData) {
        this.unprocessedData = unprocessedData;
    }

    public ProtocolLayer getHigherLayer() {
        return higherLayer;
    }

    public ProtocolLayer getLowerLayer() {
        return lowerLayer;
    }

    public void setHigherLayer(ProtocolLayer higherLayer) {
        this.higherLayer = higherLayer;
    }

    public void setLowerLayer(ProtocolLayer lowerLayer) {
        this.lowerLayer = lowerLayer;
    }

    public abstract LayerProcessingResult sendConfiguration() throws IOException;

    public abstract LayerProcessingResult sendData(Hint hint, byte[] additionalData) throws IOException;

    public LayerConfiguration<Container> getLayerConfiguration() {
        return layerConfiguration;
    }

    public void setLayerConfiguration(LayerConfiguration layerConfiguration) {
        this.layerConfiguration = layerConfiguration;
    }

    public LayerProcessingResult<Container> getLayerResult() {
        return new LayerProcessingResult(producedDataContainers);
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
        currentInputStream = null;
        unprocessedData = new ByteArrayOutputStream();
    }

    protected void addProducedContainer(Container container) {
        producedDataContainers.add(container);
    }

    public boolean executedAsPlanned() {
        int i = 0;
        for (DataContainer container : producedDataContainers) {

            if (!container.getClass().equals(layerConfiguration.getContainerList().get(i))) {
                // TODO deal with optional messages
                return false;
            }
            i++;
        }
        return true;
    }

    /**
     * A receive call which tries to read till either a timeout occurs or the configuration is fullfilled
     * 
     * @return
     * @throws IOException
     */
    public abstract LayerProcessingResult receiveData() throws IOException;

    /**
     * Tries to fill up the current Stream with more data, if instead unprocessable data (for the calling layer) is
     * produced, the data is instead cached in the next inputstream. It may be that the current input stream is null
     * when this method is called. Afterwards there should be atleast one stream not null
     * 
     * @param  hint
     * @throws IOException
     */
    public abstract void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException;

    /**
     * Returns a datastream from which currently should be read
     * 
     * @return
     * @throws IOException
     */
    public HintedInputStream getDataStream() throws IOException {
        if (currentInputStream == null) {
            receiveMoreDataForHint(null);
        }
        if (currentInputStream.available() > 0) {
            return currentInputStream;
        } else {
            if (nextInputStream != null) {
                currentInputStream = nextInputStream;
                return currentInputStream;
            } else {
                receiveMoreDataForHint(currentInputStream.getHint());
                return getDataStream();
            }
        }
    }

    /**
     * A preinitialisation function which can be called before execution is started for example to start a server socket
     * 
     * @throws IOException
     */
    public abstract void preInititialize() throws IOException;

    /**
     * An initialisation function which can be called before execution (after) the pre initalization. This can be used
     * for example to connect a client socket
     * 
     * @throws IOException
     */
    public abstract void inititialize() throws IOException;

    protected void readDataContainer(Container container, TlsContext context) throws IOException {
        Parser parser = container.getParser(context, getLowerLayer().getDataStream());
        parser.parse(container);
        Preparator preparator = container.getPreparator(context);
        preparator.prepareAfterParse(false);// TODO REMOVE THIS CLIENTMODE FLAG
        Handler handler = container.getHandler(context);
        handler.adjustContext(container);
        addProducedContainer(container);
    }
}
