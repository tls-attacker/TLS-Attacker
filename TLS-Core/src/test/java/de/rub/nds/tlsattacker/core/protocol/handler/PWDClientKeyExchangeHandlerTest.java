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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PWDClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PWDClientKeyExchangeHandlerTest {

    PWDClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PWDClientKeyExchangeHandler(context);
    }

    /**
     * Test of getParser method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof PWDClientKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PWDClientKeyExchangeMessage()) instanceof PWDClientKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PWDClientKeyExchangeMessage()) instanceof PWDClientKeyExchangeSerializer);
    }

    @Test
    public void testAdjustTLSContext() {
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.BRAINPOOLP256R1);
        context.setSelectedGroup(NamedGroup.BRAINPOOLP256R1);
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        context.setClientPWDUsername("fred");
        context.getConfig().setDefaultPWDPassword("barney");
        ECCurve curve = ECNamedCurveTable.getParameterSpec("brainpoolP256r1").getCurve();
        context.setServerPWDElement(curve.decodePoint(ArrayConverter
                .hexStringToByteArray("0422bbd56b481d7fa90c35e8d42fcd06618a0778de506b1bc38882abc73132eef37f02e13bd544acc145bdd806450d43be34b9288348d03d6cd9832487b129dbe1")));
        context.setServerPWDScalar(new BigInteger("2f704896699fc424d3cec33717644f5adf7f68483424ee51492bb96613fc4921",
                16));

        PWDClientKeyExchangeMessage message = new PWDClientKeyExchangeMessage();
        PWDClientKeyExchangePreparator prep = new PWDClientKeyExchangePreparator(context.getChooser(), message);
        prep.prepare();
        handler.adjustTLSContext(message);

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1E838FA7C9D39A38D156270777DEEE9E14270C27DE896AC0E57ACBB69AEEBE68"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("F7F68A836F08F0A0A7133301792E1189888191BC475600B7D12C6A6541BF5EFF093A70649E899CC60EDBFCC4AD0A2504"),
                context.getMasterSecret());
    }
}