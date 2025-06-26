/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ECDHClientKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                ECDHClientKeyExchangeMessage,
                ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage>> {

    public ECDHClientKeyExchangeHandlerTest() {
        super(ECDHClientKeyExchangeMessage::new, ECDHClientKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class ECDHClientKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        tlsContext.setClientRandom(new byte[] {});
        tlsContext.setServerRandom(new byte[] {});
        // set server ECDH-parameters
        tlsContext.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP192R1);
        tlsContext.setSelectedGroup(NamedGroup.SECP192R1);
        tlsContext.setServerEphemeralEcPublicKey(
                Point.createPoint(
                        new BigInteger(
                                "1336698681267683560144780033483217462176613397209956026562"),
                        new BigInteger(
                                "4390496211885670837594012513791855863576256216444143941964"),
                        (NamedEllipticCurveParameters) NamedGroup.SECP192R1.getGroupParameters()));
        tlsContext.getConfig().setDefaultClientEphemeralEcPrivateKey(new BigInteger("3"));
        tlsContext.getConfig().setDefaultServerEphemeralEcPrivateKey(new BigInteger("3"));
        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage();
        ECDHClientKeyExchangePreparator<ECDHClientKeyExchangeMessage> prep =
                new ECDHClientKeyExchangePreparator<>(tlsContext.getChooser(), message);
        prep.prepare();
        handler.adjustContext(message);
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "273CF78A3DB2E37EE97935DEF45E3C82F126807C31A498E9"),
                tlsContext.getPreMasterSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "5686D5F789AEDC43162480112E94C7C60F1292B1C5D688AE58F237BD054594775B94AC5F0B18A01B808ADBBE78BCC8C7"),
                tlsContext.getMasterSecret());
    }
}
