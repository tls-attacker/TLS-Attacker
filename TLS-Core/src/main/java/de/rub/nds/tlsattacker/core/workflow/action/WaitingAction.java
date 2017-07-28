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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class WaitingAction extends TLSAction {

    private long time;

    public WaitingAction(long time) {
        this.time = time;
    }

    public WaitingAction() {
    }

    @Override
    public void execute(TlsContext tlsContext) throws WorkflowExecutionException, IOException {
        LOGGER.info("Wating " + time + "ms...");
        try {
            Thread.sleep(time);
        } catch (InterruptedException ex) {
            Logger.getLogger(WaitingAction.class.getName()).log(Level.SEVERE, null, ex);
            // TODO executedAsPlanned = false
        }
        this.setExecuted(Boolean.TRUE);
    }

    @Override
    public void reset() {
        this.setExecuted(false);
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
