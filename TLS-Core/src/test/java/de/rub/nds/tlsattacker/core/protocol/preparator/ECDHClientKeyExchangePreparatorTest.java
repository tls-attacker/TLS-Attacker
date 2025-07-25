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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.Test;

public class ECDHClientKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                ECDHClientKeyExchangeMessage,
                ECDHClientKeyExchangePreparator<ECDHClientKeyExchangeMessage>> {

    private static final String RANDOM = "CAFEBABECAFE";
    private static final byte[] PREMASTER_SECRET =
            DataConverter.hexStringToByteArray("273CF78A3DB2E37EE97935DEF45E3C82F126807C31A498E9");

    public ECDHClientKeyExchangePreparatorTest() {
        super(ECDHClientKeyExchangeMessage::new, ECDHClientKeyExchangePreparator::new);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class ECDHClientKeyExchangePreparator.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.InvalidAlgorithmParameterException
     */
    @Test
    @Override
    public void testPrepare()
            throws NoSuchAlgorithmException,
                    NoSuchProviderException,
                    InvalidAlgorithmParameterException {
        // prepare context
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        tlsContext.setClientRandom(DataConverter.hexStringToByteArray(RANDOM));
        tlsContext.setServerRandom(DataConverter.hexStringToByteArray(RANDOM));
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

        preparator.prepare();
        assertNotNull(message.getComputations().getPublicKeyX());
        assertNotNull(message.getComputations().getPublicKeyY());
        assertArrayEquals(
                PREMASTER_SECRET, message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getPublicKeyLength().getValue());
        assertNotNull(message.getPublicKey());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                DataConverter.concatenate(
                        DataConverter.hexStringToByteArray(RANDOM),
                        DataConverter.hexStringToByteArray(RANDOM)),
                message.getComputations().getClientServerRandom().getValue());
    }
}
