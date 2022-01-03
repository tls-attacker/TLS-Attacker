/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import java.io.ByteArrayInputStream;
import org.junit.Before;
import org.junit.Test;

public class EncryptThenMacExtensionParserTest {

    private final byte[] expectedBytes = new byte[0];
    private EncryptThenMacExtensionParser parser;
    private EncryptThenMacExtensionMessage message;

    @Before
    public void setUp() {
        parser = new EncryptThenMacExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new EncryptThenMacExtensionMessage();
        parser.parse(message);
    }
}
