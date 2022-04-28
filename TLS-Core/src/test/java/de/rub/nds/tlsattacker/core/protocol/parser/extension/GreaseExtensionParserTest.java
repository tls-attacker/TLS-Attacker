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
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class GreaseExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0102030405060708090a"),
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } } });
    }

    private final byte[] extension;
    private final byte[] randomData;
    private final Config config = Config.createConfig();

    public GreaseExtensionParserTest(byte[] extension, byte[] randomData) {
        this.extension = extension;
        this.randomData = randomData;
    }

    /**
     * Test of parse method, of class HeartbeatExtensionParser.
     */
    @Test
    public void testParse() {
        TlsContext tlsContext = new TlsContext(config);
        GreaseExtensionParser parser = new GreaseExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        GreaseExtensionMessage msg = new GreaseExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(randomData, msg.getRandomData().getValue());
        assertArrayEquals(randomData, msg.getData());
    }

}
