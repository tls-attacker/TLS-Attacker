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
import de.rub.nds.tlsattacker.core.util.LogLevel;
import static de.rub.nds.tlsattacker.core.workflow.action.TlsAction.LOGGER;
import java.io.IOException;

/**
 * Print the extensions proposed by the client in ClientHello.
 */
public class PrintProposedExtensionsAction extends ConnectionBoundAction {

    public PrintProposedExtensionsAction() {
    }

    public PrintProposedExtensionsAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        TlsContext ctx = state.getTlsContext(connectionAlias);
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Proposed extensions: " + ctx.getProposedExtensions());
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
    }

}
