/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class WorkflowTraceTest {

    WorkflowTrace trace;

    public WorkflowTraceTest() {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(TlsConfig.createConfig());
        trace = factory.createFullWorkflow();
    }

}
