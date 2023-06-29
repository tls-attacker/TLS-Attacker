/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class ProtocolVersionTest {

    @ParameterizedTest
    @EnumSource(ProtocolVersion.class)
    public void testGetFromValue(ProtocolVersion providedProtocolVersion) {
        assertSame(
                providedProtocolVersion,
                ProtocolVersion.getProtocolVersion(providedProtocolVersion.getValue()));
    }

    /** Test of gethighestProtocolVersion method, of class ProtocolVersion. */
    @Test
    public void testGetHighestProtocolVersion() {
        List<ProtocolVersion> versions =
                List.of(
                        ProtocolVersion.TLS10,
                        ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12,
                        ProtocolVersion.TLS13);
        ProtocolVersion highestProtocolVersion =
                ProtocolVersion.getHighestProtocolVersion(versions);
        assertSame(ProtocolVersion.TLS13, highestProtocolVersion);
    }
}
