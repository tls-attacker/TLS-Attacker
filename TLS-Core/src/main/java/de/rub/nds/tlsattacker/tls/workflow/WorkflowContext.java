/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class WorkflowContext {

    private int actionPointer;

    private boolean proceedWorkflow;

    public WorkflowContext() {
        actionPointer = 0;
        proceedWorkflow = true;
    }

    public int getActionPointer() {
        return actionPointer;
    }

    public void setActionPointer(int actionPointer) {
        this.actionPointer = actionPointer;
    }

    public boolean isProceedWorkflow() {
        return proceedWorkflow;
    }

    public void setProceedWorkflow(boolean proceedWorkflow) {
        this.proceedWorkflow = proceedWorkflow;
    }

    public void incrementActionPointer() {
        actionPointer++;
    }

    public void decrementActionPointer() {
        actionPointer--;
    }
}
