/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowTypeDelegate extends Delegate {

    @Parameter(names = "-workflow_trace_type", description = "Type of the workflow trace (FULL or HANDSHAKE)")
    protected WorkflowTraceType workflowTraceType = WorkflowTraceType.FULL;

    public WorkflowTypeDelegate() {
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setWorkflowTraceType(workflowTraceType);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace;
        switch (workflowTraceType) {
            case FULL:
                trace = factory.createFullWorkflow();
                break;
            case HANDSHAKE:
                trace = factory.createHandshakeWorkflow();
                break;
            case CLIENT_HELLO:
                trace = factory.createClientHelloWorkflow();
                break;
            default:
                throw new ConfigurationException("not supported workflow type: " + config.getWorkflowTraceType());
        }
        config.setWorkflowTrace(trace);
    }

}
