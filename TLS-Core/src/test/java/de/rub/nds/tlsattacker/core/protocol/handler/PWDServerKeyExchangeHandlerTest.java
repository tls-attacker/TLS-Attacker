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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PWDServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PWDServerKeyExchangeHandlerTest {

    PWDServerKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PWDServerKeyExchangeHandler(context);
    }

    /**
     * Test of getParser method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof PWDServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PWDServerKeyExchangeMessage()) instanceof PWDServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PWDServerKeyExchangeMessage()) instanceof PWDServerKeyExchangeSerializer);
    }

    @Test
    public void testAdjustTLSContext() {
        PWDServerKeyExchangeMessage message = new PWDServerKeyExchangeMessage();
        message.setNamedGroup(NamedGroup.BRAINPOOLP256R1.getValue());
        byte[] element = ArrayConverter
                .hexStringToByteArray("0422bbd56b481d7fa90c35e8d42fcd06618a0778de506b1bc38882abc73132eef37f02e13bd544acc145bdd806450d43be34b9288348d03d6cd9832487b129dbe1");
        BigInteger scalar = new BigInteger("2f704896699fc424d3cec33717644f5adf7f68483424ee51492bb96613fc4921", 16);
        byte[] salt = ArrayConverter
                .hexStringToByteArray("963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3");
        message.setElement(element);
        message.setScalar(scalar.toByteArray());
        message.setSalt(salt);
        handler.adjustTLSContext(message);

        assertArrayEquals(
                ArrayConverter.bigIntegerToByteArray(PointFormatter
                        .formatFromByteArray(NamedGroup.BRAINPOOLP256R1, element).getX().getData()),
                ArrayConverter.bigIntegerToByteArray(context.getServerPWDElement().getX().getData()));
        assertArrayEquals(salt, context.getServerPWDSalt());
        assertArrayEquals(scalar.toByteArray(), context.getServerPWDScalar().toByteArray());
        assertEquals(NamedGroup.BRAINPOOLP256R1, context.getSelectedGroup());
    }
}
