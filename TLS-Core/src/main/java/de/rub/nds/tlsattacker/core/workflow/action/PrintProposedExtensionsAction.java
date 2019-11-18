/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Print the extensions proposed by the client in ClientHello.
 */
public class PrintProposedExtensionsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public PrintProposedExtensionsAction() {
    }

    public PrintProposedExtensionsAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext ctx = state.getTlsContext(connectionAlias);
        CONSOLE.info("Proposed extensions: " + ctx.getProposedExtensions());
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
    }

}
