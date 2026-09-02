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
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChangeQuicPacketNumberAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Integer packetNumber = null;

    public ChangeQuicPacketNumberAction() {}

    public ChangeQuicPacketNumberAction(int packetNumber) {
        this.packetNumber = packetNumber;
    }

    protected abstract void changePacketNumber(QuicContext quicContext);

    @Override
    public void execute(State state) throws ActionExecutionException {
        QuicContext quicContext = state.getContext(getConnectionAlias()).getQuicContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        changePacketNumber(quicContext);
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
