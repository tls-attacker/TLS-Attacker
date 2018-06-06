/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.WorkflowTraceTypeConverter;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class MitmWorkflowTypeDelegate extends Delegate {

    @Parameter(names = "-mitm_workflow_type", description = "Type of the workflow trace (currently only SIMPLE_MITM_PROXY, RSA_SYNC_PROXY)", converter = WorkflowTraceTypeConverter.class)
    private WorkflowTraceType workflowTraceType = WorkflowTraceType.SIMPLE_MITM_PROXY;

    public MitmWorkflowTypeDelegate() {
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    @Override
    public void applyDelegate(Config config) {
        if (workflowTraceType != null) {
            config.setWorkflowTraceType(workflowTraceType);
        }
    }
}