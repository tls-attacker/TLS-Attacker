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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

public class ECDHClientKeyExchangePreparatorTest {

    private final static String RANDOM = "CAFEBABECAFE";
    private final static byte[] PREMASTER_SECRET = ArrayConverter
            .hexStringToByteArray("273CF78A3DB2E37EE97935DEF45E3C82F126807C31A498E9");
    private TlsContext context;
    private ECDHClientKeyExchangeMessage message;
    private ECDHClientKeyExchangePreparator preparator;

    public ECDHClientKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());

        context = new TlsContext();
        message = new ECDHClientKeyExchangeMessage();
        preparator = new ECDHClientKeyExchangePreparator(context.getChooser(), message);
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
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP192R1);
        context.setSelectedGroup(NamedGroup.SECP192R1);
        context.setServerEcPublicKey(Point.createPoint(new BigInteger(
                "1336698681267683560144780033483217462176613397209956026562"), new BigInteger(
                "4390496211885670837594012513791855863576256216444143941964"), NamedGroup.SECP192R1));
        context.getConfig().setDefaultClientEcPrivateKey(new BigInteger("3"));

        preparator.prepare();
        assertNotNull(message.getComputations().getPublicKeyX());
        assertNotNull(message.getComputations().getPublicKeyY());
        assertArrayEquals(PREMASTER_SECRET, message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getPublicKeyLength().getValue());
        assertNotNull(message.getPublicKey());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)), message.getComputations().getClientServerRandom()
                        .getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
