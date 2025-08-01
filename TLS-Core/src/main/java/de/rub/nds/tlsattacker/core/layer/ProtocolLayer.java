/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstracts a message layer (TCP, UDP, IMAP, etc.). Each layer knows of the layer below and above
 * itself. It can send messages using the layer below and forward received messages to the layer
 * above.
 *
 * @param <Hint> Some layers need a hint which message they should send or receive.
 * @param <Container> The kind of messages/Containers this layer is able to send and receive.
 */
public abstract class ProtocolLayer<
        ContextType extends Context,
        Hint extends LayerProcessingHint,
        Container extends DataContainer> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ProtocolLayer<ContextType, Hint, Container> higherLayer = null;

    private ProtocolLayer<ContextType, Hint, Container> lowerLayer = null;

    private LayerConfiguration<Container> layerConfiguration;

    private List<Container> producedDataContainers;

    private boolean reachedTimeout = false;

    protected HintedInputStream currentInputStream = null;

    protected HintedInputStream nextInputStream = null;

    private LayerType layerType;

    private byte[] unreadBytes;

    protected ProtocolLayer(LayerType layerType) {
        producedDataContainers = new LinkedList<>();
        this.layerType = layerType;
        this.unreadBytes = new byte[0];
    }

    public ProtocolLayer<ContextType, Hint, Container> getHigherLayer() {
        return higherLayer;
    }

    public ProtocolLayer<ContextType, Hint, Container> getLowerLayer() {
        return lowerLayer;
    }

    public void setHigherLayer(ProtocolLayer<ContextType, Hint, Container> higherLayer) {
        this.higherLayer = higherLayer;
    }

    public void setLowerLayer(ProtocolLayer<ContextType, Hint, Container> lowerLayer) {
        this.lowerLayer = lowerLayer;
    }

    public abstract LayerProcessingResult<Container> sendConfiguration() throws IOException;

    public abstract LayerProcessingResult<Container> sendData(
            LayerProcessingHint hint, byte[] additionalData) throws IOException;

    public LayerConfiguration<Container> getLayerConfiguration() {
        return layerConfiguration;
    }

    @SuppressWarnings("unchecked")
    public void setLayerConfiguration(LayerConfiguration<?> layerConfiguration) {
        this.layerConfiguration = (LayerConfiguration<Container>) layerConfiguration;
    }

    public LayerProcessingResult<Container> getLayerResult() {
        boolean isExecutedAsPlanned = executedAsPlanned();
        return new LayerProcessingResult<>(
                producedDataContainers, getLayerType(), isExecutedAsPlanned, getUnreadBytes());
    }

    public boolean executedAsPlanned() {
        boolean isExecutedAsPlanned = true;
        if (getLayerConfiguration() != null) {
            isExecutedAsPlanned = getLayerConfiguration().executedAsPlanned(producedDataContainers);
        }
        return isExecutedAsPlanned;
    }

    /** Sets input stream to null if empty. Throws an exception otherwise. */
    public void removeDrainedInputStream() {
        try {
            if (currentInputStream != null && currentInputStream.available() > 0) {
                throw new RuntimeException("Trying to drain a non-empty inputStream");
            } else {
                currentInputStream = null;
            }
        } catch (IOException ex) {
            LOGGER.error("Could not evaluate Stream availability. Removing Stream anyways", ex);
            currentInputStream = null;
        }
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
        currentInputStream = null;
        nextInputStream = null;
        reachedTimeout = false;
    }

    protected void addProducedContainer(Container container) {
        producedDataContainers.add(container);
    }

    protected boolean containerAlreadyUsedByHigherLayer(Container container) {
        if (producedDataContainers == null) {
            return false;
        }
        // must check for identical references here
        return producedDataContainers.stream()
                .anyMatch(listedContainer -> listedContainer == container);
    }

    /**
     * A receive call which tries to read till either a timeout occurs or the configuration is
     * fullfilled
     *
     * @return LayerProcessingResult Contains information about the execution of the receive action.
     */
    public abstract LayerProcessingResult<Container> receiveData();

    /**
     * Tries to fill up the current Stream with more data, if instead unprocessable data (for the
     * calling layer) is produced, the data is instead cached in the next inputstream. It may be
     * that the current input stream is null when this method is called.
     *
     * @param hint This hint from the calling layer specifies which data its wants to read.
     * @throws IOException Some layers might produce IOExceptions when sending or receiving data
     *     over sockets etc.
     */
    public abstract void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException;

    /**
     * Returns a datastream from which currently should be read
     *
     * @return The next data stream with data available.
     * @throws IOException Some layers might produce IOExceptions when sending or receiving data
     *     over sockets etc.
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
     * Evaluates if more data can be retrieved for parsing immediately, i.e without receiving on the
     * lowest layer.
     *
     * @return true if more data is available in any receive buffer
     */
    public boolean isDataBuffered() {
        LOGGER.debug("Checking if data is buffered: {}", getLayerType());
        try {
            if ((currentInputStream != null && currentInputStream.available() > 0)
                    || nextInputStream != null && nextInputStream.available() > 0) {
                LOGGER.debug("Data buffered in current stream");
                return true;
            } else if (getLowerLayer() != null) {
                LOGGER.debug("Checking if lower layer has data buffered");
                return getLowerLayer().isDataBuffered();
            }
            LOGGER.debug("No data is buffered in this layer or lower layers");
            return false;
        } catch (IOException e) {
            // with exceptions on reading our inputStreams we can not read more data
            LOGGER.error("No more data can be read from the inputStreams", e);
            return false;
        }
    }

    public boolean shouldContinueProcessing() {
        LOGGER.debug(
                "Deciding if we should continue...: {} type: {}", layerConfiguration, layerType);
        if (layerConfiguration != null) {
            return layerConfiguration.shouldContinueProcessing(
                    getLayerResult().getUsedContainers(), reachedTimeout, isDataBuffered());

        } else {
            LOGGER.debug("Checking if data is buffered since no layer configuration exists");
            return isDataBuffered();
        }
    }

    public LayerType getLayerType() {
        return layerType;
    }

    /**
     * Parses and handles content from a container.
     *
     * @param container The container to handle.
     * @param context The context of the connection. Keeps parsed and handled values.
     */
    protected void readDataContainer(Container container, Context context) {
        HintedInputStream inputStream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream", e);
            return;
        }

        readDataContainer(container, context, inputStream);
    }

    /**
     * Parses and handles content from a container.
     *
     * @param container The container to handle.
     * @param context The context of the connection. Keeps parsed and handled values.
     */
    protected void readDataContainer(
            Container container, Context context, InputStream inputStream) {
        Parser parser = container.getParser(context, inputStream);

        try {
            parser.parse(container);
            if (container.shouldPrepare()) {
                Preparator preparator = container.getPreparator(context);
                preparator.prepareAfterParse();
            }
            Handler handler = container.getHandler(context);
            handler.adjustContext(container);
            addProducedContainer((Container) container);
        } catch (RuntimeException ex) {
            setUnreadBytes(parser.getAlreadyParsed());
        }
    }

    public byte[] getUnreadBytes() {
        return unreadBytes;
    }

    public void setUnreadBytes(byte[] unreadBytes) {
        this.unreadBytes = unreadBytes;
    }

    public boolean prepareDataContainer(DataContainer dataContainer, Context context) {
        if (dataContainer.shouldPrepare()) {
            Preparator preparator = dataContainer.getPreparator(context);
            try {
                preparator.prepare();
                preparator.afterPrepare();
            } catch (PreparationException ex) {
                LOGGER.error(
                        "Could not prepare message {}. Therefore, we skip it.", dataContainer, ex);
                return false;
            }
        }
        return true;
    }

    public List<Container> getUnprocessedConfiguredContainers() {
        if (getLayerConfiguration() == null || getLayerConfiguration().getContainerList() == null) {
            return new LinkedList<>();
        } else if (producedDataContainers == null) {
            return new LinkedList<>(getLayerConfiguration().getContainerList());
        }
        return getLayerConfiguration().getContainerList().stream()
                .filter(Predicate.not(producedDataContainers::contains))
                .collect(Collectors.toList());
    }

    public void setReachedTimeout(boolean reachedTimeout) {
        this.reachedTimeout = reachedTimeout;
    }

    public boolean hasReachedTimeout() {
        return reachedTimeout;
    }
}
