/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 *
 * @author Robert Merget
 */
public class UnknownExtensionHandlerTest {

    // ExtensionMessages we should be able to parse
    private String[] extensions = { "000b000403000102", "000a000a0008001d001700190018", "00230000",
            "000d0020001e040305030603080408050806040105010601020302010202040205020602", "00160000", "00170000" };

    // TODO more than real world
    /**
     * Tests that the UnknownExtensionHandler is able to parse real unknown
     * extensions
     */
    @Test
    public void testParseExtension() {
        for (int i = 0; i < extensions.length; i++) {
            UnknownExtensionHandler extensionHandler = new UnknownExtensionHandler();
            int length = extensionHandler.parseExtension(ArrayConverter.hexStringToByteArray(extensions[i]), 0);
            LOGGER.debug(extensionHandler.extensionMessage);
            assertTrue(length == extensions[i].length() / 2);
        }
    }

    private static final Logger LOGGER = LogManager.getLogger(UnknownExtensionHandlerTest.class);

}
