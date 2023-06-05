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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class PWDClientKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                PWDClientKeyExchangeMessage, PWDClientKeyExchangePreparator> {

    private static final byte[] salt =
            ArrayConverter.hexStringToByteArray(
                    "963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3");

    private static final byte[] scalar =
            ArrayConverter.hexStringToByteArray(
                    "46D60B797558FACE1E8243463DC0C16D3324FEA8BE7C0BEC87FB1E1D4EB7CE59");

    private static final byte[] element =
            ArrayConverter.hexStringToByteArray(
                    ("04 46 E2 DA 64 A0 BB 0E  2A 48 5C EC 20 89 FD 47\n"
                                    + "96 2C D8 8D FA 7F 06 B0  4A 00 84 1D 19 EA B3 7B\n"
                                    + "6A 01 27 F3 25 2A 21 9D  02 9C 28 B1 0F A1 12 A0\n"
                                    + "B7 16 F3 84 37 FA 56 B9  4B EB 3D 3D D5 8D ED 94\n"
                                    + "7B")
                            .replaceAll("\\s+", ""));

    private static final byte[] premaster =
            ArrayConverter.hexStringToByteArray(
                    "3B29832D64C2359A955BBEE5A466F5C8E9D25529056729C2FFDE0E04DD9D11BE");

    public PWDClientKeyExchangePreparatorTest() {
        super(PWDClientKeyExchangeMessage::new, PWDClientKeyExchangePreparator::new);
        context.setSelectedGroup(NamedGroup.BRAINPOOLP256R1);
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.getConfig().setDefaultServerPWDSalt(salt);
        context.getConfig().setDefaultClientPWDUsername("fred");
        context.getConfig().setDefaultPWDPassword("barney");
        context.setServerPWDScalar(new BigInteger(scalar));
        context.setServerPWDElement(
                PointFormatter.formatFromByteArray(NamedGroup.BRAINPOOLP256R1, element));
        context.getConfig()
                .setDefaultClientPWDMask(
                        ArrayConverter.hexStringToByteArray(
                                "3EBAF8986DA712C82BCD4D554BF0B54023C29B624DE9EF9C2F931EFC580F9AFB"));
        context.getConfig()
                .setDefaultClientPWDPrivate(
                        ArrayConverter.hexStringToByteArray(
                                "081B12E107B1E805F2B4F5F0F1D00C2D0F62634670921C505867FF20F6A8335E"));
    }

    @Test
    @Override
    public void testPrepare() {
        preparator.prepareHandshakeMessageContents();
        assertEquals(32, message.getScalarLength().getValue());
        assertArrayEquals(scalar, message.getScalar().getValue());
        assertEquals(65, message.getElementLength().getValue());
        assertArrayEquals(element, message.getElement().getValue());
        assertArrayEquals(premaster, message.getComputations().getPremasterSecret().getValue());
    }
}
