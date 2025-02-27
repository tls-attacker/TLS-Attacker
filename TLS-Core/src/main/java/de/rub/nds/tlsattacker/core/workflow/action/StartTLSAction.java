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
 * This action inserts the {@link MessageLayer} and {@link RecordLayer} into the {@link LayerStack} at runtime to enable opportunistic
 * TLS communication. If the MessageLayer and RecordLayer are already present in the LayerStack,
 * they will be removed. Even though it does not transmit the actual application-specific STARTTLS
 * command, it should only be used in protocols that support a form of STARTTLS command. Currently,
 * only SMTP is supported.
 */
@XmlRootElement
public class StartTLSAction extends ConnectionBoundAction {
    protected static final Logger LOGGER = LogManager.getLogger();

    /**
     * This action dynamically inserts Record and Message layer from the StarttlsContext into the
     * LayerStack during runtime. It is designed to work with protocols that define an explicit
     * mechanism for upgrading from plain communication to TLS (often called "STARTTLS"). The action
     * only works with such protocols and will throw an exception if the highest layer in the
     * LayerStack does not fit. For now, only SMTP is supported. Users are still responsible for
     * performing the actual STARTTLS command in the protocol and adding a TLS handshake to the
     * WorkflowTrace.
     *
     * @param state the state to work on
     * @throws ActionExecutionException if action is not supported for the current protocol
     * @throws ActionExecutionException if action is already executed
     */
    @Override
    public void execute(State state) throws ActionExecutionException {
        LayerType topLevelType =
                state.getContext().getLayerStack().getHighestLayer().getLayerType();
        // only SMTP is supported for now, because explicit application command for upgrading is
        // needed
        if (topLevelType != ImplementedLayers.SMTP) {
            throw new ActionExecutionException("STARTTLS is not defined for this protocol: " + topLevelType);
        }
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LayerStack layerStack = state.getContext().getLayerStack();
        int targetedLayerIndex = layerStack.getLayersInStack().indexOf(topLevelType);

        // use common TlsContext, but save the old layers in StarttlsContext
        // allows use to enable and disable STARTTLS multiple times
        TlsContext tlsContext = state.getTlsContext();
        StarttlsContext starttlsContext = state.getStarttlsContext();

        if (!layerStack.getLayersInStack().contains(ImplementedLayers.MESSAGE)
                && !layerStack.getLayersInStack().contains(ImplementedLayers.RECORD)) {
            if (starttlsContext.getMessageLayer() == null) {
                starttlsContext.setMessageLayer(new MessageLayer(tlsContext));
            }
            if (starttlsContext.getRecordLayer() == null) {
                starttlsContext.setRecordLayer(new RecordLayer(tlsContext));
            }
            layerStack.insertLayer(starttlsContext.getRecordLayer(), targetedLayerIndex + 1);
            layerStack.insertLayer(starttlsContext.getMessageLayer(), targetedLayerIndex + 1);
            setExecuted(true);
        } else {
            LOGGER.warn("At least one of the layers is already present in the LayerStack, skipping StartTLS");
            setExecuted(false);
        }
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
