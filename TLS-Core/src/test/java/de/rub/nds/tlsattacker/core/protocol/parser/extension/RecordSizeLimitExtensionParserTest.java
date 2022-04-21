/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class RecordSizeLimitExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("2000"), ArrayConverter.hexStringToByteArray("2000") } });
    }

    private final byte[] extension;
    private final byte[] recordSizeLimit;
    private final Config config = Config.createConfig();

    public RecordSizeLimitExtensionParserTest(byte[] extension, byte[] recordSizeLimit) {
        this.extension = extension;
        this.recordSizeLimit = recordSizeLimit;
    }

    /**
     * Test of parseExtensionMessageContent method of class RecordSizeLimitExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        TlsContext tlsContext = new TlsContext(config);
        RecordSizeLimitExtensionParser parser =
            new RecordSizeLimitExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        RecordSizeLimitExtensionMessage message = new RecordSizeLimitExtensionMessage();
        parser.parse(message);
        assertArrayEquals(recordSizeLimit, message.getRecordSizeLimit().getValue());
    }
}
