/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.Config;

public class DynamicWorkflowDelegate extends Delegate {

    public DynamicWorkflowDelegate() {}

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
