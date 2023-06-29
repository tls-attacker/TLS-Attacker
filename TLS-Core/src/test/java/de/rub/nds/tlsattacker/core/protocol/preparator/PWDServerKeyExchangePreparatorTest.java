/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import org.junit.jupiter.api.Test;

public class PWDServerKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                PWDServerKeyExchangeMessage, PWDServerKeyExchangePreparator> {

    private static final byte[] salt =
            ArrayConverter.hexStringToByteArray(
                    "963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3");

    private static final byte[] scalar =
            ArrayConverter.hexStringToByteArray(
                    "46D60B797558FACE1E8243463DC0C16D3324FEA8BE7C0BEC87FB1E1D4EB7CE59");

    private static final byte[] element =
            ArrayConverter.hexStringToByteArray(
                    ("0446E2DA64A0BB0E2A485CEC2089FD47962CD88DFA7F06B04A00841D19EAB37B6A0127F3252A219D029C28B10FA112A0B716F38437FA56B94BEB3D3DD58DED947B"));

    public PWDServerKeyExchangePreparatorTest() {
        super(PWDServerKeyExchangeMessage::new, PWDServerKeyExchangePreparator::new);
        context.setClientNamedGroupsList(NamedGroup.BRAINPOOLP256R1);
        context.getConfig().setDefaultServerNamedGroups(NamedGroup.BRAINPOOLP256R1);
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.setConnection(new InboundConnection());
        context.getConfig().setDefaultServerPWDSalt(salt);
        context.getConfig().setDefaultClientPWDUsername("fred");
        context.getConfig().setDefaultPWDPassword("barney");
        context.getConfig()
                .setDefaultServerPWDMask(
                        ArrayConverter.hexStringToByteArray(
                                "3EBAF8986DA712C82BCD4D554BF0B54023C29B624DE9EF9C2F931EFC580F9AFB"));
        context.getConfig()
                .setDefaultServerPWDPrivate(
                        ArrayConverter.hexStringToByteArray(
                                "081B12E107B1E805F2B4F5F0F1D00C2D0F62634670921C505867FF20F6A8335E"));
    }

    @Test
    @Override
    public void testPrepare() {
        preparator.prepareHandshakeMessageContents();
        assertEquals(EllipticCurveType.NAMED_CURVE.getValue(), message.getGroupType().getValue());
        assertArrayEquals(
                NamedGroup.BRAINPOOLP256R1.getValue(), message.getNamedGroup().getValue());
        assertEquals(32, message.getSaltLength().getValue());
        assertArrayEquals(salt, message.getSalt().getValue());
        assertEquals(32, message.getScalarLength().getValue());
        assertArrayEquals(scalar, message.getScalar().getValue());
        assertEquals(65, message.getElementLength().getValue());
        assertArrayEquals(element, message.getElement().getValue());
    }
}
