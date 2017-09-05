/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangeHandlerTest {

    private ECDHClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ECDHClientKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ECDHClientKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ECDHClientKeyExchangeMessage()) instanceof ECDHClientKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ECDHClientKeyExchangeMessage()) instanceof ECDHClientKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage();
        message.prepareComputations();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setRecordLayer(new TlsRecordLayer(context));
        message.getComputations()
                .setPremasterSecret(
                        ArrayConverter
                                .hexStringToByteArray("6df5c76b9e4488beb41b9b01f5256999a8980a8e4636e3afa43316cebc2c9829"));
        message.getComputations()
                .setClientRandom(
                        ArrayConverter
                                .hexStringToByteArray("217bb5c7d0072bd1ccbb014bf5730046e77333f6775fa2b0862b57cde886c035594d13478175ba43c46a37b48867a24a8109baddbc28f685e52af70d18ba4ceb"));

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);

        handler.adjustTLSContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("6df5c76b9e4488beb41b9b01f5256999a8980a8e4636e3afa43316cebc2c9829"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("09DFD94B0DE26E2EE34201D79D1963C8C47C06162AD9BD5A7F116E4DC7C4F6E42D63088ED5BBDAE650E450A8B7295148"),
                context.getMasterSecret());
    }
}
