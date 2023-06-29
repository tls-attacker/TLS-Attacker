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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ECDHClientKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                ECDHClientKeyExchangeMessage<?>,
                ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage<?>>> {

    public ECDHClientKeyExchangeHandlerTest() {
        super(ECDHClientKeyExchangeMessage::new, ECDHClientKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class ECDHClientKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        context.setClientRandom(new byte[] {});
        context.setServerRandom(new byte[] {});
        // set server ECDH-parameters
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP192R1);
        context.setSelectedGroup(NamedGroup.SECP192R1);
        context.setServerEcPublicKey(
                Point.createPoint(
                        new BigInteger(
                                "1336698681267683560144780033483217462176613397209956026562"),
                        new BigInteger(
                                "4390496211885670837594012513791855863576256216444143941964"),
                        NamedGroup.SECP192R1));
        context.getConfig().setDefaultClientEcPrivateKey(new BigInteger("3"));
        context.getConfig().setDefaultServerEcPrivateKey(new BigInteger("3"));
        ECDHClientKeyExchangeMessage<?> message = new ECDHClientKeyExchangeMessage<>();
        ECDHClientKeyExchangePreparator<ECDHClientKeyExchangeMessage<?>> prep =
                new ECDHClientKeyExchangePreparator<>(context.getChooser(), message);
        prep.prepare();
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "273CF78A3DB2E37EE97935DEF45E3C82F126807C31A498E9"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "5686D5F789AEDC43162480112E94C7C60F1292B1C5D688AE58F237BD054594775B94AC5F0B18A01B808ADBBE78BCC8C7"),
                context.getMasterSecret());
    }
}
