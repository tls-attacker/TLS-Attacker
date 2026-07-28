/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This action changes the <code>enabled</code> flag for one or more layers, which allows modifying
 * the LayerStack at runtime.
 */
@XmlRootElement
public abstract class ChangeLayerEnabledAction extends ConnectionBoundAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private boolean executedAsPlanned = true;
    // JAXB does not support Interfaces, so we have to use the concrete enum here, which is not
    // ideal, we would prefer to use the LayerType interface but alas
    private final List<ImplementedLayers> targetedLayers;

    /**
     * If set, targeted layers that the layer stack does not contain are skipped instead of failing
     * the action. This allows targeting the layers of several alternative stacks without knowing
     * which one the connection actually uses.
     */
    private boolean ignoreMissingLayers = false;

    protected ChangeLayerEnabledAction() {
        // JAXB constructor
        this.targetedLayers = new ArrayList<>();
    }

    /**
     * Creates a new instance of ChangeLayerEnabledAction.
     *
     * @param targetedLayers the layer(s) to change
     */
    public ChangeLayerEnabledAction(ImplementedLayers... targetedLayers) {
        this.targetedLayers = new ArrayList<>(List.of(targetedLayers));
    }

    /**
     * Creates a new instance of ChangeLayerEnabledAction that tolerates targeted layers which are
     * not part of the layer stack.
     *
     * @param ignoreMissingLayers whether targeted layers missing from the stack are skipped instead
     *     of failing the action
     * @param targetedLayers the layer(s) to change
     */
    public ChangeLayerEnabledAction(
            boolean ignoreMissingLayers, ImplementedLayers... targetedLayers) {
        this(targetedLayers);
        this.ignoreMissingLayers = ignoreMissingLayers;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        executedAsPlanned = true;
        for (LayerType layerType : targetedLayers) {
            ProtocolLayer<?, ?, ?> layer = state.getContext().getLayerStack().getLayer(layerType);
            if (layer != null) {
                layer.setEnabled(layerPredicate(layer));
                LOGGER.debug("Set layer {} enabled to {}", layerType, layer.isEnabled());
            } else if (ignoreMissingLayers) {
                LOGGER.debug("Layer {} is not part of the layer stack, skipping it", layerType);
            } else {
                executedAsPlanned = false;
            }
        }
        setExecuted(true);
    }

    /**
     * Returns whether targeted layers missing from the layer stack are skipped instead of failing
     * the action.
     *
     * @return true if missing layers are ignored
     */
    public boolean isIgnoreMissingLayers() {
        return ignoreMissingLayers;
    }

    /**
     * Returns the layers this action toggles.
     *
     * @return the targeted layers
     */
    public List<ImplementedLayers> getTargetedLayers() {
        return targetedLayers;
    }

    /**
     * Given a layer, this method determines what the updated enabled state should be.
     *
     * @param layer the layer to check
     * @return true if the layer should be enabled, false otherwise
     */
    public abstract boolean layerPredicate(ProtocolLayer<?, ?, ?> layer);

    /**
     * Checks whether the layers supposed to be toggled were able to be found in the layer stack. If
     * not, the action was not executed as planned.
     *
     * <p>It is important to note that this method does not check whether the active layers were
     * actually changed, only whether they were found (i.e., EnableLayerAction will execute as
     * planned for an already enabled layer).
     *
     * @return true if the action was executed as planned, false otherwise
     */
    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    /** Resets the executed state of the action */
    @Override
    public void reset() {
        setExecuted(false);
        executedAsPlanned = false;
    }
}
