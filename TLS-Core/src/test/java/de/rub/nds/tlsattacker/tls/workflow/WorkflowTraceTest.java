/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(new TlsConfig());
        trace = factory.createFullWorkflow();
    }

    @Test
    public void testDeepCopy() {
        WorkflowTrace copy = (WorkflowTrace) UnoptimizedDeepCopy.copy(trace);
        assertEquals("The number of messages in both traces has to be equal", trace.getAllConfiguredMessages().size(),
                copy.getAllConfiguredMessages().size());
    }

}
