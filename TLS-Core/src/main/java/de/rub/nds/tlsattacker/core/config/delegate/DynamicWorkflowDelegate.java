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

public class DynamicWorkflowDelegate extends Delegate {

    @Parameter(names = "-dynamic_workflow", description = "If this parameter is set, the workflow is only initialized with a ClientHello message (not yet implemented)")
    private Boolean dynamicWorkflow = null;

    public DynamicWorkflowDelegate() {
    }

    public Boolean isDynamicWorkflow() {
        throw new UnsupportedOperationException("DynamicWorkflow is currently not supported.");
    }

    public void setDynamicWorkflow(boolean dynamicWorkflow) {
        throw new UnsupportedOperationException("DynamicWorkflow is currently not supported.");
    }

    @Override
    public void applyDelegate(Config config) {
        throw new UnsupportedOperationException("DynamicWorkflow is currently not supported.");
    }

}
