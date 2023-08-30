/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import org.junit.jupiter.api.Test;

public class ConfigSchemaGeneratorTest {

    /** Test of main method, of class WorkflowTraceSchemaGenerator. */
    @Test
    public void generateResourceSchema() {
        ConfigSchemaGenerator.main(new String[] {"../resources/schema/"});
        ConfigSchemaGenerator.main(new String[] {"src/main/resources/"});
    }
}
