/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
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
public class DynamicWorkflowDelegate extends Delegate {

    @Parameter(names = "-dynamic_workflow", description = "If this parameter is set, the workflow is only initialized with a ClientHello message (not yet implemented)")
    private Boolean dynamicWorkflow = null;

    public DynamicWorkflowDelegate() {
    }

    public Boolean isDynamicWorkflow() {
        return dynamicWorkflow;
    }

    public void setDynamicWorkflow(boolean dynamicWorkflow) {
        this.dynamicWorkflow = dynamicWorkflow;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (dynamicWorkflow != null) {
            config.setDynamicWorkflow(dynamicWorkflow);
        }
    }

}
