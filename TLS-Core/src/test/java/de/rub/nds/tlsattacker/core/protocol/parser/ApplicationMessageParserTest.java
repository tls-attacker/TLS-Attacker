/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ApplicationMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
            .asList(new Object[][] { { new byte[] { 0, 1, 2, 3, 4, 5, 6 } }, { new byte[] { 2, 3, 4, 5, 6 } } });
    }

    private final byte[] message;
    private final Config config = Config.createConfig();

    public ApplicationMessageParserTest(byte[] message) {
        this.message = message;
    }

    /**
     * Test of parse method, of class ApplicationMessageParser.
     */
    @Test
    public void testParse() {
        ApplicationMessageParser parser =
            new ApplicationMessageParser(new ByteArrayInputStream(message), ProtocolVersion.TLS12, config);
        ApplicationMessage applicationMessage = new ApplicationMessage();
        parser.parse(applicationMessage);
        assertArrayEquals(applicationMessage.getCompleteResultingMessage().getValue(), message);
        assertArrayEquals(applicationMessage.getData().getValue(), message);
    }

}
