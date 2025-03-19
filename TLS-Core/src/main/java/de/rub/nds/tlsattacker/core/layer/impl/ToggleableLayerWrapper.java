/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.workflow.action.DisableLayerAction;
import de.rub.nds.tlsattacker.core.workflow.action.EnableLayerAction;
import de.rub.nds.tlsattacker.core.workflow.action.ToggleLayerAction;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A wrapper for a {@link ProtocolLayer} that can be toggled on and off.
 *
 * <p>If the layer is inactive, it will not send nor receive any data specified by its own {@link
 * LayerConfiguration}.
 *
 * <p>Data supplied via {@link #sendData(LayerProcessingHint, byte[])} will be passed through the
 * layer unchanged.
 *
 * <p>Data containers that are explicitly given via the different layer configuration will not be
 * sent if the layer is inactive. Furthermore, they will fail the corresponding action call if
 * {@link #isThrowOnDataContainerWhenInactive()} (default is true).
 *
 * <p>The intended use case of this class is to allow for easy toggling of layers in the LayerStack
 * via the {Enable, Disable, Toggle}LayerAction.
 *
 * <p><b>Important:</b>The ToggleableLayerWrapper is intended to be used for optional intermediate
 * layers and assumes a lower layer. While this assumption is not enforced, it is not supported to
 * use a toggleable layer as the lowest layer in the stack.
 *
 * @param <H>
 * @param <C>
 * @see EnableLayerAction
 * @see DisableLayerAction
 * @see ToggleLayerAction
 */
public class ToggleableLayerWrapper<H extends LayerProcessingHint, C extends DataContainer>
        extends ProtocolLayer<H, C> {

    private final ProtocolLayer<H, C> wrappedLayer;
    private boolean active = true;
    // normally the layer should throw an exception if it is not active and sendConfiguration is
    // called (because it indicates a misconfigured workflow)
    // however, I can imagine that there are cases where this is not desired (proxy perhaps?), so
    // this can be toggled for now
    private boolean throwOnDataContainerWhenInactive = true;

    /**
     * Constructor for the ToggleableLayerWrapper with the layer active at the beginning
     *
     * @param wrappedLayer the layer to wrap
     */
    public ToggleableLayerWrapper(ProtocolLayer<H, C> wrappedLayer) {
        this(wrappedLayer, true, true);
    }

    /**
     * Constructor for the ToggleableLayerWrapper
     *
     * @param wrappedLayer the layer to wrap
     * @param active whether the layer is active at the beginning
     */
    public ToggleableLayerWrapper(ProtocolLayer<H, C> wrappedLayer, boolean active) {
        this(wrappedLayer, active, true);
    }

    /**
     * Constructor for the ToggleableLayerWrapper
     *
     * @param wrappedLayer the layer to wrap
     * @param active whether the layer is active at the beginning
     */
    public ToggleableLayerWrapper(
            ProtocolLayer<H, C> wrappedLayer,
            boolean active,
            boolean throwOnDataContainerWhenInactive) {
        super(wrappedLayer.getLayerType());
        this.wrappedLayer = wrappedLayer;
        wrappedLayer.setLowerLayer(this.getLowerLayer());
        wrappedLayer.setHigherLayer(this);
        this.active = active;
        this.throwOnDataContainerWhenInactive = throwOnDataContainerWhenInactive;
    }

    public ProtocolLayer<H, C> getWrappedLayer() {
        return wrappedLayer;
    }

    /**
     * Sends data containers that match the type of the wrapped layer and are explicitly given via
     * the different layer configuration.
     *
     * @return
     * @throws IOException
     */
    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        if (this.active) {
            return wrappedLayer.sendConfiguration();
        } else if (throwOnDataContainerWhenInactive) {
            // see the comments above
            throw new IOException("Tried to send configuration of an inactive layer");
        } else {
            return new LayerProcessingResult<>(new ArrayList<>(), getLayerType(), true);
        }
    }

    @Override
    public LayerProcessingResult sendData(H hint, byte[] additionalData) throws IOException {
        if (this.active) {
            return wrappedLayer.sendData(hint, additionalData);
        } else {
            return getLowerLayer().sendData(hint, additionalData);
        }
    }

    @Override
    public LayerProcessingResult receiveData() {
        if (this.active) {
            return wrappedLayer.receiveData();
        } else {
            return new LayerProcessingResult<>(new ArrayList<>(), getLayerType(), true);
        }
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        if (this.active) {
            wrappedLayer.receiveMoreDataForHint(hint);
        } else {
            getLowerLayer().receiveMoreDataForHint(hint);
        }
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public LayerType getLayerType() {
        return wrappedLayer.getLayerType();
    }

    @Override
    public void clear() {
        wrappedLayer.clear();
    }

    @Override
    public LayerConfiguration<C> getLayerConfiguration() {
        return wrappedLayer.getLayerConfiguration();
    }

    @Override
    public void setLayerConfiguration(LayerConfiguration layerConfiguration) {
        wrappedLayer.setLayerConfiguration(layerConfiguration);
    }

    @Override
    public LayerProcessingResult<C> getLayerResult() {
        if (this.active) {
            return wrappedLayer.getLayerResult();
        } else {
            return new LayerProcessingResult<>(new ArrayList<>(), getLayerType(), true);
        }
    }

    @Override
    public boolean executedAsPlanned() {
        if (this.active) {
            return wrappedLayer.executedAsPlanned();
        } else {
            return true;
        }
    }

    @Override
    public void removeDrainedInputStream() {
        wrappedLayer.removeDrainedInputStream();
    }

    @Override
    public HintedInputStream getDataStream() throws IOException {
        if (this.active) {
            return wrappedLayer.getDataStream();
        } else {
            return getLowerLayer().getDataStream();
        }
    }

    @Override
    public boolean isDataBuffered() {
        if (this.active) {
            return wrappedLayer.isDataBuffered();
        } else {
            return getLowerLayer().isDataBuffered();
        }
    }

    @Override
    public boolean shouldContinueProcessing() {
        if (this.active) {
            return wrappedLayer.shouldContinueProcessing();
        } else {
            return false;
        }
    }

    @Override
    public byte[] getUnreadBytes() {
        return wrappedLayer.getUnreadBytes();
    }

    @Override
    public void setUnreadBytes(byte[] unreadBytes) {
        wrappedLayer.setUnreadBytes(unreadBytes);
    }

    @Override
    public boolean prepareDataContainer(DataContainer dataContainer, LayerContext context) {
        return wrappedLayer.prepareDataContainer(dataContainer, context);
    }

    @Override
    public List<C> getUnprocessedConfiguredContainers() {
        if (this.active) {
            return wrappedLayer.getUnprocessedConfiguredContainers();
        } else {
            return new ArrayList<>();
        }
    }

    @Override
    public void setLowerLayer(ProtocolLayer lowerLayer) {
        super.setLowerLayer(lowerLayer);
        wrappedLayer.setLowerLayer(lowerLayer);
    }

    @Override
    public void setHigherLayer(ProtocolLayer higherLayer) {
        super.setHigherLayer(higherLayer);
        wrappedLayer.setHigherLayer(higherLayer);
    }

    public boolean isThrowOnDataContainerWhenInactive() {
        return throwOnDataContainerWhenInactive;
    }

    public void setThrowOnDataContainerWhenInactive(boolean throwOnDataContainerWhenInactive) {
        this.throwOnDataContainerWhenInactive = throwOnDataContainerWhenInactive;
    }
}
