/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class ConfigSchemaGeneratorIT {

    /**
     * Test of main method, of class WorkflowTraceSchemaGenerator.
     */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void generateResourceSchema() {
        ConfigSchemaGenerator.main(new String[] { "../resources/schema/" });
        ConfigSchemaGenerator.main(new String[] { "src/main/resources/" });
    }
}
