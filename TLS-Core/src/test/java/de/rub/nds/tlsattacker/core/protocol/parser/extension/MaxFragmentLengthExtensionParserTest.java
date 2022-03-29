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
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class MaxFragmentLengthExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {});// TODO collect a real
        // maxFragmentLength extension
    }

    private final byte[] extension;
    private final byte[] maxFragmentLength;
    private final Config config = Config.createConfig();

    public MaxFragmentLengthExtensionParserTest(byte[] extension, byte[] maxFragmentLength) {
        this.extension = extension;
        this.maxFragmentLength = maxFragmentLength;
    }

    /**
     * Test of parseExtensionMessageContent method, of class MaxFragmentLengthExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        TlsContext tlsContext = new TlsContext(config);
        MaxFragmentLengthExtensionParser parser =
            new MaxFragmentLengthExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        parser.parse(msg);
        assertTrue(maxFragmentLength == msg.getMaxFragmentLength().getValue());
    }
}
