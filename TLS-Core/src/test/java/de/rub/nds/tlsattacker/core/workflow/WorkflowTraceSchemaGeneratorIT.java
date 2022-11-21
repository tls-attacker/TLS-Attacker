/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * @author ic0ns
 */
public class WorkflowTraceSchemaGeneratorIT {

    /** Test of main method, of class WorkflowTraceSchemaGenerator. */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void generateResourceSchema() {
        WorkflowTraceSchemaGenerator.main(new String[] {"../resources/schema/"});
        WorkflowTraceSchemaGenerator.main(new String[] {"src/main/resources/"});
    }
}
