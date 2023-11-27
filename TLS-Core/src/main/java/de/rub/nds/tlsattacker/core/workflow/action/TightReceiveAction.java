/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@XmlRootElement(name = "TightReceive")
public class TightReceiveAction extends MessageAction {

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> expectedMessages = new ArrayList<>();

    public TightReceiveAction() {}

    public TightReceiveAction(List<ProtocolMessage> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public TightReceiveAction(ProtocolMessage... expectedMessages) {
        super();
        this.expectedMessages = Arrays.asList(expectedMessages);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving tightly...");

        tightReceive(tlsContext, expectedMessages);

        setExecuted(true);

        String expected = getReadableStringFromContainerList(expectedMessages);
        LOGGER.debug("Receive Expected:" + expected);
        String received =
                getReadableStringFromContainerList(messages, httpMessages, quicPackets, quicFrames);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Containers: " + received);
        } else {
            LOGGER.info("Received Containers (" + getConnectionAlias() + "): " + received);
        }
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    LOGGER.warn(
                            "ReceiveAction failed: Layer {}, did not execute as planned",
                            result.getLayerType());
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        fragments = null;
        quicFrames = null;
        quicPackets = null;
        setExecuted(null);
    }
}
