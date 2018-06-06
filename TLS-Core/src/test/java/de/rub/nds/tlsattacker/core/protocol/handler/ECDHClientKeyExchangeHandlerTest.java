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
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ECDHClientKeyExchangeHandlerTest {

    private ECDHClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
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
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        context.setClientRandom(new byte[] {});
        context.setServerRandom(new byte[] {});

        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage();
        ECDHClientKeyExchangePreparator prep = new ECDHClientKeyExchangePreparator(context.getChooser(), message);
        prep.prepare();

        handler.adjustTLSContext(message);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("A3B5299147537E6696500AB8CD870DB3BA78303DE749DFBA"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("01F395D34D67E2DF13E19BC94F407D3FC97B440A55F65F7F807219672316C36F761384E8F468D1404E9C2C9083A3CD41"),
                context.getMasterSecret());
    }
}
