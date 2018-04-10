/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class DefaultFilterTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private WorkflowTrace trace;
    private final Config config;
    private final DefaultFilter filter;

    public DefaultFilterTest() {
        config = Config.createConfig();
        filter = new DefaultFilter(config);
    }

    @Test
    public void filterUninitializedTraceFails() {
        trace = new WorkflowTrace();

        exception.expect(ConfigurationException.class);
        exception.expectMessage("Workflow trace not well defined. Trace does not define any connections.");
        filter.applyFilter(trace);
    }

}
