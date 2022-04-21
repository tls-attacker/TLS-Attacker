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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECPointFormatExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("03000102"), ArrayConverter.hexStringToByteArray("03000102"),
                ExtensionType.EC_POINT_FORMATS, 4, 3, new byte[] { 0, 1, 2 } } }); // is the same for TLS10 and TLS11
    }

    private byte[] extension;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int pointFormatLength;
    private byte[] pointFormats;
    private final Config config = Config.createConfig();

    public ECPointFormatExtensionParserTest(byte[] extension, byte[] completeExtension, ExtensionType type,
        int extensionLength, int pointFormatLength, byte[] pointFormats) {
        this.extension = extension;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.pointFormatLength = pointFormatLength;
        this.pointFormats = pointFormats;
    }

    /**
     * Test of parseExtensionMessageContent method, of class ECPointFormatExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        TlsContext tlsContext = new TlsContext(config);
        ECPointFormatExtensionParser parser =
            new ECPointFormatExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(msg.getPointFormats().getValue(), pointFormats);
        assertTrue(pointFormatLength == msg.getPointFormatsLength().getValue());
    }
}
