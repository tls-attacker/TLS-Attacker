/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.List;

public class WorkFlowTraceFakeExecutor {
    public static void execute(WorkflowTrace trace) {
        List<TlsAction> actionList = trace.getTlsActions();
        for (TlsAction action : actionList) {
            action.setExecuted(Boolean.TRUE);
        }
    }

    private WorkFlowTraceFakeExecutor() {
    }
}
