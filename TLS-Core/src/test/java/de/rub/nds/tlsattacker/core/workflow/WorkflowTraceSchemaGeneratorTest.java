/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import org.junit.jupiter.api.Test;

/**
 * @author ic0ns
 */
public class WorkflowTraceSchemaGeneratorTest {

    /** Test of main method, of class WorkflowTraceSchemaGeneratorTest. */
    @Test
    public void generateResourceSchema() {
        WorkflowTraceSchemaGenerator.main(new String[] {"../resources/schema/"});
        WorkflowTraceSchemaGenerator.main(new String[] {"src/main/resources/"});
    }
}
