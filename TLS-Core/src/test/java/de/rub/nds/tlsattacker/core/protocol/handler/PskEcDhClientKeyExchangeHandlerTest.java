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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskEcDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskEcDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskEcDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PskEcDhClientKeyExchangeHandlerTest {

    private PskEcDhClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PskEcDhClientKeyExchangeHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class PskEcDhClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof PskEcDhClientKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class PskEcDhClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PskEcDhClientKeyExchangeMessage()) instanceof PskEcDhClientKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class PskEcDhClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PskEcDhClientKeyExchangeMessage()) instanceof PskEcDhClientKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class
     * PskEcDhClientKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        PskEcDhClientKeyExchangeMessage message = new PskEcDhClientKeyExchangeMessage();
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setRecordLayer(new TlsRecordLayer(context));
        message.getComputations()
                .setPremasterSecret(
                        ArrayConverter
                                .hexStringToByteArray("0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"));
        message.getComputations()
                .setClientServerRandom(
                        ArrayConverter
                                .hexStringToByteArray("a449532975d478abeefcfafa7522b9312bdbd0bb294fe460c4d52bab13a425b7594d0e9508874a67db6d9b8e91db4f38600e88f006bbe58f2b41deb6811c74cc"));

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);

        handler.adjustTLSContext(message);
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("FA1D499E795E936751AD43355C26857728E78ABE1C4BCAFA6EF3C90F6D9B9E49DF1ADE262F127EB2A23BB73E142EE122"),
                context.getMasterSecret());
    }
}
