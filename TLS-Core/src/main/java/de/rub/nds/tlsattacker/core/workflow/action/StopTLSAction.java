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
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.StarttlsContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This action removes the {@link MessageLayer} and {@link RecordLayer} from the {@link LayerStack} at runtime and stores them for later.
 * If the MessageLayer and RecordLayer are not present in the LayerStack, nothing happens.
 * This class is the counterpart to the {@link StartTLSAction} and is designed to be used with application protocols that support a form of opportunistic TLS.
 */
@XmlRootElement
public class StopTLSAction extends ConnectionBoundAction {
    protected static final Logger LOGGER = LogManager.getLogger();

    /**
     * This action dynamically removes Record and Message layer from the
     * LayerStack during runtime and store them into StarttlsContext for later use.
     * TODO: since the action is now STARTTLS agnostic, we should adjust StarttlsContext too
     *
     * @param state the state to work on
     * @throws ActionExecutionException if action is not supported for the current protocol
     * @throws ActionExecutionException if action is already executed
     */
    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LayerStack layerStack = state.getContext().getLayerStack();

        // save the old layers in StarttlsContext
        // allows use to enable and disable STARTTLS multiple times
        if (layerStack.getLayersInStack().contains(ImplementedLayers.MESSAGE)) {
            ProtocolLayer oldMessageLayer = layerStack.removeLayer(MessageLayer.class);
            state.getStarttlsContext().setMessageLayer((MessageLayer) oldMessageLayer);
        }
        if (layerStack.getLayersInStack().contains(ImplementedLayers.RECORD)) {
            ProtocolLayer oldRecordLayer = layerStack.removeLayer(RecordLayer.class);
            state.getStarttlsContext().setRecordLayer((RecordLayer) oldRecordLayer);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
