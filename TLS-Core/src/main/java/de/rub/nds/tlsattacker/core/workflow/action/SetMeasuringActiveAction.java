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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Allows the user to enable / disable measuring when using the TimingClientTcpTransportHandler.
 * Disabling the measurements prevents TLS-Attacker from receiving in the middle of a flight if
 * multiple SendActions are used. To enable measurements, place this action immediately before the
 * last SendAction.
 */
@XmlRootElement
public class SetMeasuringActiveAction extends ConnectionBoundAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private boolean valueToSet = false;
    boolean asPlanned = false;

    public SetMeasuringActiveAction() {}

    public SetMeasuringActiveAction(boolean valueToSet) {
        this.valueToSet = valueToSet;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TransportHandler transportHandler =
                state.getTlsContext(getConnectionAlias()).getTransportHandler();
        if (transportHandler instanceof TimeableTransportHandler) {
            TimeableTransportHandler timeableTransportHandler =
                    (TimeableTransportHandler) transportHandler;
            timeableTransportHandler.setMeasuringActive(valueToSet);
            LOGGER.debug("Set measuringActive in transport handler to {}", valueToSet);
            asPlanned = true;
        } else {
            LOGGER.warn(
                    "Can't enable or disable measurements as transport handler is not suited to collect measurements");
        }
    }

    @Override
    public void reset() {
        asPlanned = false;
    }

    @Override
    public boolean executedAsPlanned() {
        return asPlanned;
    }
}
