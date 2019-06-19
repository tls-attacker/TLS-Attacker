/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class PWDServerKeyExchangePreparatorTest {

    private TlsContext tlsContext;
    private PWDServerKeyExchangeMessage msg;
    private PWDServerKeyExchangePreparator preparator;

    private byte[] salt = ArrayConverter
            .hexStringToByteArray("963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3");

    private byte[] scalar = ArrayConverter
            .hexStringToByteArray("46D60B797558FACE1E8243463DC0C16D3324FEA8BE7C0BEC87FB1E1D4EB7CE59");

    private byte[] element = ArrayConverter.hexStringToByteArray(("04 46 E2 DA 64 A0 BB 0E  2A 48 5C EC 20 89 FD 47\n"
            + "96 2C D8 8D FA 7F 06 B0  4A 00 84 1D 19 EA B3 7B\n"
            + "6A 01 27 F3 25 2A 21 9D  02 9C 28 B1 0F A1 12 A0\n"
            + "B7 16 F3 84 37 FA 56 B9  4B EB 3D 3D D5 8D ED 94\n" + "7B").replaceAll("\\s+", ""));

    @Before
    public void setUp() throws Exception {
        this.tlsContext = new TlsContext();

        tlsContext.setClientNamedGroupsList(NamedGroup.BRAINPOOLP256R1);
        tlsContext.setServerNamedGroupsList(NamedGroup.BRAINPOOLP256R1);
        tlsContext.setClientRandom(ArrayConverter
                .hexStringToByteArray("528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        tlsContext.setServerRandom(ArrayConverter
                .hexStringToByteArray("528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.getConfig().setDefaultServerPWDSalt(salt);
        tlsContext.getConfig().setDefaultClientPWDUsername("fred");
        tlsContext.getConfig().setDefaultPWDPassword("barney");
        tlsContext
                .getConfig()
                .setDefaultServerPWDMask(
                        ArrayConverter
                                .hexStringToByteArray("3EBAF8986DA712C82BCD4D554BF0B54023C29B624DE9EF9C2F931EFC580F9AFB"));
        tlsContext
                .getConfig()
                .setDefaultServerPWDPrivate(
                        ArrayConverter
                                .hexStringToByteArray("081B12E107B1E805F2B4F5F0F1D00C2D0F62634670921C505867FF20F6A8335E"));
        msg = new PWDServerKeyExchangeMessage();
        preparator = new PWDServerKeyExchangePreparator(tlsContext.getChooser(), msg);
    }

    @Test
    public void testPrepareHandshakeMessageContents() {
        preparator.prepareHandshakeMessageContents();
        assertEquals(EllipticCurveType.NAMED_CURVE.getValue(), (long) msg.getGroupType().getValue());
        assertArrayEquals(NamedGroup.BRAINPOOLP256R1.getValue(), msg.getNamedGroup().getValue());
        assertEquals(32, (long) msg.getSaltLength().getValue());
        assertArrayEquals(salt, msg.getSalt().getValue());
        assertEquals(32, (long) msg.getScalarLength().getValue());
        assertArrayEquals(scalar, msg.getScalar().getValue());
        assertEquals(65, (long) msg.getElementLength().getValue());
        assertArrayEquals(element, msg.getElement().getValue());
    }
}