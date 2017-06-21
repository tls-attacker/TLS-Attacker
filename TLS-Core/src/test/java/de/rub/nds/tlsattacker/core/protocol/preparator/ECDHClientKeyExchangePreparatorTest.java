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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Malena Ebert - malena-rub@ebert.li
 */
public class ECDHClientKeyExchangePreparatorTest {

    private TlsContext context;
    private ECDHClientKeyExchangeMessage message;
    private ECDHClientKeyExchangePreparator preparator;
    private final static String RANDOM = "CAFEBABECAFE";
    private final static byte[] SERVER_PUB_KEY = ArrayConverter
            .hexStringToByteArray("023683c91035ad3815282ce7a4a273678487fa031f802508c2");
    private final static byte[] PREMASTER_SECRET = ArrayConverter
            .hexStringToByteArray("81d3ba4e7a54eea7c584cf487bd6bea7dcfc27201f42a543");
    private final static byte[] MASTER_SECRET = ArrayConverter
            .hexStringToByteArray("44569804ebaef0c715a08bfea7272396c74bc75a3e1cf5c68cf6026286c27a1ddfcac31488692f14691fc8de62042004");

    public ECDHClientKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new ECDHClientKeyExchangeMessage();
        preparator = new ECDHClientKeyExchangePreparator(context, message);
        RandomHelper.setRandom(new Random(0));
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * ECDHClientKeyExchangePreparator.
     * 
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.InvalidAlgorithmParameterException
     */
    @Test
    public void testPrepare() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        // prepare context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        // set server ECDH-parameters
        X9ECParameters curve = X962NamedCurves.getByName("prime192v1");
        context.setServerECPublicKeyParameters(new ECPublicKeyParameters(curve.getCurve().decodePoint(SERVER_PUB_KEY),
                new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN())));

        preparator.prepareHandshakeMessageContents();

        // Tests
        assertNotNull(message.getPublicKeyBaseX());
        assertNotNull(message.getPublicKeyBaseY());
        assertArrayEquals(PREMASTER_SECRET, message.getComputations().getPremasterSecret().getValue());
        assertArrayEquals(MASTER_SECRET, message.getComputations().getMasterSecret().getValue());
        assertEquals(HandshakeByteLength.MASTER_SECRET, message.getComputations().getMasterSecret().getValue().length);
        assertNotNull(message.getSerializedPublicKeyLength().getValue());
        assertNotNull(message.getSerializedPublicKey());
        assertNotNull(message.getComputations().getClientRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)), message.getComputations().getClientRandom()
                        .getValue());
    }
}
