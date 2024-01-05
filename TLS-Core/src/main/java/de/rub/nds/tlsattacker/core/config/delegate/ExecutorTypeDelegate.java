/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;

public class ExecutorTypeDelegate extends Delegate {

    @Parameter(names = "-executor_type", description = "Type of the workflow trace executor")
    private WorkflowExecutorType executorType = null;

    public ExecutorTypeDelegate() {}

    public WorkflowExecutorType getWorkflowTraceType() {
        return executorType;
    }

    public void setWorkflowTraceType(WorkflowExecutorType executorType) {
        this.executorType = executorType;
    }

    @Override
    public void applyDelegate(Config config) {
        if (executorType != null) {
            config.setWorkflowExecutorType(executorType);
        }
    }
}
