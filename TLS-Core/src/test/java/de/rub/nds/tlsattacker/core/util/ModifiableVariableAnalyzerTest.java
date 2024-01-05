/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ModifiableVariableAnalyzerTest {

    /** Test of getAllModifiableVariableFields method, of class ModifiableVariableAnalyzer. */
    @Test
    public void testGetAllModifiableVariableFields() {
        ClientHelloMessage chm = new ClientHelloMessage(Config.createConfig());
        String[] fieldNames = {
            "compressionLength",
            "cipherSuiteLength",
            "cipherSuites",
            "compressions",
            "protocolVersion",
            "unixTime",
            "random",
            "sessionIdLength",
            "sessionId",
            "type",
            "completeResultingMessage"
        };
        List<Field> fields = ModifiableVariableAnalyzer.getAllModifiableVariableFields(chm);
        for (String fn : fieldNames) {
            assertTrue(containsFieldName(fn, fields));
        }
        assertFalse(containsFieldName("somename", fields));
    }

    /** Test of getRandomModifiableVariableField method, of class ModifiableVariableAnalyzer. */
    @Test
    @Disabled("Not implemented")
    public void testGetRandomModifiableVariableField() {}

    private boolean containsFieldName(String name, List<Field> list) {
        for (Field f : list) {
            if (f.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }
}
