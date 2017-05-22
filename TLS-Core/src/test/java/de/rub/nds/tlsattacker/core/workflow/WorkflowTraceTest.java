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
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import org.junit.Test;
import static org.junit.Assert.*;

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

    @Test
    public void testDeepCopy() {
        WorkflowTrace copy = (WorkflowTrace) UnoptimizedDeepCopy.copy(trace);
        assertEquals("The number of messages in both traces has to be equal", trace.getAllConfiguredMessages().size(),
                copy.getAllConfiguredMessages().size());
    }

}
