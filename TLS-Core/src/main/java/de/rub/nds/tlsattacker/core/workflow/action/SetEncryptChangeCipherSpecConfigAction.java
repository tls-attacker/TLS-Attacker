/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;

/**
 * Specifies whether a CCS is sent encrypted if encryption is active
 */
public class SetEncryptChangeCipherSpecConfigAction extends ConnectionBoundAction {

    boolean setting = false;

    public SetEncryptChangeCipherSpecConfigAction() {
    }

    public SetEncryptChangeCipherSpecConfigAction(boolean setting) {
        this.setting = setting;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        state.getConfig().setEncryptChangeCipherSpec(setting);
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
