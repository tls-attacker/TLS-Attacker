/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstracts a message layer (TCP, UDP, IMAP, etc.). Each layer knows of the layer below and above itself. It can send
 * messages using the layer below and forward received messages to the layer above.
 *
 * @param <Hint>
 *                    Some layers need a hint which message they should send or receive.
 * @param <Container>
 *                    The kind of messages/Containers this layer is able to send and receive.
 */
public abstract class ProtocolLayer<Hint extends LayerProcessingHint, Container extends DataContainer> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ProtocolLayer higherLayer = null;

    private ProtocolLayer lowerLayer = null;

    private LayerConfiguration<Container> layerConfiguration;

    private List<Container> producedDataContainers;

    protected HintedInputStream currentInputStream = null;

    protected HintedInputStream nextInputStream = null;

    private LayerType layerType;

    public ProtocolLayer(LayerType layerType) {
        producedDataContainers = new LinkedList<>();
        this.layerType = layerType;
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
        boolean isExecutedAsPlanned = true;
        if (getLayerConfiguration() != null) {
            isExecutedAsPlanned = getLayerConfiguration().executedAsPlanned(producedDataContainers);
        }
        return new LayerProcessingResult(producedDataContainers, getLayerType(), isExecutedAsPlanned);
    }

    /**
     * Sets input stream to null if empty. Throws an exception otherwise.
     */
    public void removeDrainedInputStream() {
        try {
            if (currentInputStream != null && currentInputStream.available() > 0) {
                throw new RuntimeException("Trying to drain a non-empty inputStream");
            } else {
                currentInputStream = null;
            }
        } catch (IOException ex) {
            LOGGER.error("Could not evaluate Stream availability. Removing Stream anyways");
            currentInputStream = null;
        }
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
        currentInputStream = null;
        nextInputStream = null;
    }

    protected void addProducedContainer(Container container) {
        producedDataContainers.add(container);
    }

    /**
     * A receive call which tries to read till either a timeout occurs or the configuration is fullfilled
     *
     * @return             LayerProcessingResult Contains information about the execution of the receive action.
     * @throws IOException
     *                     Some layers might produce IOExceptions when sending or receiving data over sockets etc.
     */
    public abstract LayerProcessingResult receiveData() throws IOException;

    /**
     * Tries to fill up the current Stream with more data, if instead unprocessable data (for the calling layer) is
     * produced, the data is instead cached in the next inputstream. It may be that the current input stream is null
     * when this method is called.
     *
     * @param  hint
     *                     This hint from the calling layer specifies which data its wants to read.
     * @throws IOException
     *                     Some layers might produce IOExceptions when sending or receiving data over sockets etc.
     */
    public abstract void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException;

    /**
     * Returns a datastream from which currently should be read
     *
     * @return             The next data stream with data available.
     * @throws IOException
     *                     Some layers might produce IOExceptions when sending or receiving data over sockets etc.
     */
    public HintedInputStream getDataStream() throws IOException {
        if (currentInputStream == null) {
            receiveMoreDataForHint(null);
            if (currentInputStream == null) {
                throw new EndOfStreamException(
                    "Could not receive data stream from lower layer, nothing more to receive");
            }
        }
        if (currentInputStream.available() > 0) {
            return currentInputStream;
        } else {
            if (nextInputStream != null) {
                currentInputStream = nextInputStream;
                return currentInputStream;
            } else {
                LOGGER.debug("Trying to get datastream while no data is available");
                this.receiveMoreDataForHint(null);
                return currentInputStream;
            }
        }
    }

    /**
     * Evaluates if more data can be retrieved for parsing immediately, i.e without receiving on the lowest layer.
     *
     * @return             true if more data is available in any receive buffer
     * @throws IOException
     */
    public boolean isDataBuffered() throws IOException {
        if ((currentInputStream != null && currentInputStream.available() > 0)
            || nextInputStream != null && nextInputStream.available() > 0) {
            return true;
        } else if (getLowerLayer() != null) {
            return getLowerLayer().isDataBuffered();
        }
        return false;
    }

    public boolean shouldContinueProcessing() throws IOException {
        if (layerConfiguration != null) {
            return layerConfiguration.successRequiresMoreContainers(getLayerResult().getUsedContainers())
                || (isDataBuffered() && ((ReceiveLayerConfiguration) layerConfiguration).isProcessTrailingContainers());
        } else {
            return isDataBuffered();
        }
    }

    /**
     * Parses and handles content from a container.
     *
     * @param  container
     *                     The container to handle.
     * @param  context
     *                     The context of the connection. Keeps parsed and handled values.
     * @throws IOException
     *                     Should a lower layer not be able to return a data stream.
     */
    protected void readDataContainer(Container container, TlsContext context) throws IOException {
        Parser parser = container.getParser(context, getLowerLayer().getDataStream());
        parser.parse(container);
        Preparator preparator = container.getPreparator(context);
        preparator.prepareAfterParse(false);// TODO REMOVE THIS CLIENTMODE FLAG
        Handler handler = container.getHandler(context);
        handler.adjustContext(container);
        addProducedContainer(container);
    }

    public LayerType getLayerType() {
        return layerType;
    }
}
