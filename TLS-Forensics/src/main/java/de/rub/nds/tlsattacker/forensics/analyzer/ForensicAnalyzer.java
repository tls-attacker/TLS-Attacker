package de.rub.nds.tlsattacker.forensics.analyzer;

import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

/**
 * This class tries to reconstruct WorkflowTraces
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ForensicAnalyzer {

    public ForensicAnalyzer() {
    }

    public WorkflowTrace getRealWorkflowTrace(WorkflowTrace executedWorkflow) {
        return executedWorkflow;
    }
}
