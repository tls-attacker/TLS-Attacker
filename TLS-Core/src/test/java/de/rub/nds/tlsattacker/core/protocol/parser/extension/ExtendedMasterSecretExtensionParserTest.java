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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[0] } });
    }

    private final byte[] expectedBytes;
    private ExtendedMasterSecretExtensionParser parser;
    private ExtendedMasterSecretExtensionMessage message;
    private final Config config = Config.createConfig();

    public ExtendedMasterSecretExtensionParserTest(byte[] expectedBytes) {
        this.expectedBytes = expectedBytes;
    }

    @Before
    public void setUp() {
        TlsContext tlsContext = new TlsContext(config);
        parser = new ExtendedMasterSecretExtensionParser(new ByteArrayInputStream(expectedBytes), tlsContext);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new ExtendedMasterSecretExtensionMessage();
        parser.parse(message);
    }

}
