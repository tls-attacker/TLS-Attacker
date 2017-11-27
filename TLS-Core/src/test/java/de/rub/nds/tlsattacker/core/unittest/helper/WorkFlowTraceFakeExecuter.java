/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.List;

public class WorkFlowTraceFakeExecuter {
    public static void execute(WorkflowTrace trace) {
        List<TlsAction> actionList = trace.getTlsActions();
        for (TlsAction action : actionList) {
            action.setExecuted(Boolean.TRUE);
        }
    }

    private WorkFlowTraceFakeExecuter() {
    }
}
