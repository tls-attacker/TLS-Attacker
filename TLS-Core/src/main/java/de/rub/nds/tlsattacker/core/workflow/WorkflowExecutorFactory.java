/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WorkflowExecutorFactory {

    public static WorkflowExecutor createWorkflowExecutor(WorkflowExecutorType type, TlsContext tlsContext) {
        switch (type) {
            case DEFAULT:
                return new DefaultWorkflowExecutor(tlsContext);
            default:
                throw new UnsupportedOperationException(type.name() + " not yet implemented");
        }
    }

    private WorkflowExecutorFactory() {
    }
}
