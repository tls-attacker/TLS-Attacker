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
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import java.io.IOException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ResetConnectionAction extends TLSAction {

    public ResetConnectionAction() {
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException, IOException {
        LOGGER.info("Terminating Connection");
        tlsContext.getTransportHandler().closeConnection();
        LOGGER.info("Reopening Connection");
        tlsContext.getTransportHandler().initialize();
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

}
