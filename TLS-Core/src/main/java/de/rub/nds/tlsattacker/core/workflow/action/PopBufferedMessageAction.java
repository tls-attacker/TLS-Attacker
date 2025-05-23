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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "PopBufferedMessage")
public class PopBufferedMessageAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean couldPop = false;

    public PopBufferedMessageAction() {
        super();
    }

    public PopBufferedMessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());
        if (context.getMessageBuffer().isEmpty()) {
            LOGGER.warn("Could not pop message from buffer, buffer is empty");
            couldPop = false;
        } else {
            LOGGER.info("Popping message from buffer");
            context.getMessageBuffer().pop();
            couldPop = true;
        }
        setExecuted(Boolean.TRUE);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted() && couldPop;
    }

    @Override
    public void reset() {
        couldPop = false;
        setExecuted(false);
    }
}
