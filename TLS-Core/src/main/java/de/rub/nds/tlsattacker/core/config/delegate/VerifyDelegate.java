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
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class VerifyDelegate extends Delegate {

    @Parameter(names = "-verify_workflow_correctness", description = "If this parameter is set, the workflow correctness is evaluated after the worklow stops. This involves"
            + "checks on the protocol message sequences.")
    private Boolean verifyWorkflowCorrectness = null;

    public VerifyDelegate() {
    }

    public Boolean isVerifyWorkflowCorrectness() {
        return verifyWorkflowCorrectness;
    }

    public void setVerifyWorkflowCorrectness(boolean verifyWorkflowCorrectness) {
        this.verifyWorkflowCorrectness = verifyWorkflowCorrectness;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (verifyWorkflowCorrectness != null) {
            config.setVerifyWorkflow(verifyWorkflowCorrectness);
        }
    }

}
