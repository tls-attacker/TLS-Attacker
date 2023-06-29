/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DefaultFilterTest {

    private DefaultFilter filter;

    @BeforeEach
    public void setUp() {
        Config config = Config.createConfig();
        filter = new DefaultFilter(config);
    }

    @Test
    public void testFilterUninitializedTraceFails() {
        WorkflowTrace trace = new WorkflowTrace();
        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> filter.applyFilter(trace));
        assertEquals(
                "Workflow trace not well defined. Trace does not define any connections.",
                exception.getMessage());
    }
}
