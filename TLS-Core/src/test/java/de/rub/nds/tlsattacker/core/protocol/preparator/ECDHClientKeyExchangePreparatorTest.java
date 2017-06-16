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
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
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
    final static String RANDOM = "CAFEBABECAFE";

    public ECDHClientKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new ECDHClientKeyExchangeMessage();
        preparator = new ECDHClientKeyExchangePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * ECDHClientKeyExchangePreparator.
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.InvalidAlgorithmParameterException
     */
    @Test
    public void testPrepare() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //prepare context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        //set server ECDH-parameters
        X9ECParameters curve = X962NamedCurves.getByName("prime192v1");
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECDomainParameters domainParameters = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN());
        generator.init(new ECKeyGenerationParameters(domainParameters, RandomHelper.getBadSecureRandom()));
        AsymmetricCipherKeyPair ecKeyPair = generator.generateKeyPair();
        context.setServerECPublicKeyParameters((ECPublicKeyParameters)ecKeyPair.getPublic());


        preparator.prepareHandshakeMessageContents();


        //Tests
        assertNotNull(
                message.getPublicKeyBaseX()
        );
        assertNotNull(
                message.getPublicKeyBaseY()
        );
        assertArrayEquals(
                TlsECCUtils.calculateECDHBasicAgreement(
                        new ECPublicKeyParameters(
                                domainParameters.getCurve().createPoint(
                                        message.getPublicKeyBaseX().getValue(),
                                        message.getPublicKeyBaseY().getValue()),
                                domainParameters
                        ),
                        (ECPrivateKeyParameters) ecKeyPair.getPrivate()
                ),
                message.getComputations().getPremasterSecret().getValue()
        );
        assertNotNull(
                message.getComputations().getMasterSecret().getValue()
        );
        assertEquals(
                HandshakeByteLength.MASTER_SECRET,
                message.getComputations().getMasterSecret().getValue().length
        );
        assertNotNull(
                message.getSerializedPublicKeyLength().getValue()
        );
        assertNotNull(
                message.getSerializedPublicKey()
        );
        assertNotNull(
                message.getComputations().getClientRandom()
        );
        assertArrayEquals(
                ArrayConverter.concatenate(
                        ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)
                ),
                message.getComputations().getClientRandom().getValue()
        );
    }

}
