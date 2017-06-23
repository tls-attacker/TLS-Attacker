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
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessagePreparatorTest {
    private static final Logger LOGGER = LogManager.getLogger(CertificateMessagePreparatorTest.class);

    private CertificateVerifyMessage message;
    private TlsContext context;
    private CertificateVerifyMessagePreparator preparator;

    @Before
    public void setUp() {
        message = new CertificateVerifyMessage();
        context = new TlsContext();
        preparator = new CertificateVerifyMessagePreparator(context, message);
        RandomHelper.getRandom().setSeed(0);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * CertificateVerifyMessagePreparator.
     *
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testPrepareRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SignatureAlgorithm.RSA.getJavaName());
        generator.initialize(1024, new BadRandom());
        KeyPair pair = generator.genKeyPair();
        context.getConfig().setPrivateKey(pair.getPrivate());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.NONE));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.MD5));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1));
        context.getConfig().setSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        assertArrayEquals(new byte[] { 1, 1, }, message.getSignatureHashAlgorithm().getValue());
        // TODO I dont check if the signature is correctly calcualted or
        // calculated over the correct values
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("479FB09700E855666B1D65C9C5B0D279088A0573A7FDA4F59E5816E7869CA7753F7648143F9A7DB86534D33EEA9ED40BB8FE052F5BAF1D9BE52502B57B6B5661F9A4DC077D4AC0714F5768D7319C6E3862BD6EFA2F85E464B54E8A89FC19FD2090E53DA05D5556E74A7EE31CD217A510620BD61F24F5CDFEF5ACDFE060B9F37E"),
                message.getSignature().getValue());
        assertTrue(message.getSignatureLength().getValue() == 128);
    }

    @Test
    public void testPrepareEC() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
        generator.initialize(256, new BadRandom());
        KeyPair pair = generator.genKeyPair();
        context.getConfig().setPrivateKey(pair.getPrivate());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("308193020100301306072A8648CE3D020106082A8648CE3D03010704793077020101042060B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C0325F41DA00A06082A8648CE3D030107A14403420004188C19D1FB6B00E8CEBB3CC0F236A5F440AAD3D7DAFC772D3342998FBD9E0A5DD3FF3D42FCD2A9B39B021E2ED50D66CC49EB594AE63951DA5F8BEC0F3247CA1B"),
                pair.getPrivate().getEncoded());
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.NONE));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.NONE));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1));
        algoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1));
        context.getConfig().setSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getSignature().getValue(), false));

        assertArrayEquals(new byte[] { 2, 3 }, message.getSignatureHashAlgorithm().getValue());
        // TODO I dont check if the signature is correctly calcualted or
        // calculated over the correct values
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("30440220188C19D1FB6B00E8CEBB3CC0F236A5F440AAD3D7DAFC772D3342998FBD9E0A5D022033EFCB876620D040614EB7D7E82E76AB12558CCBBA1147F5059C99DDE16C5B39"),
                message.getSignature().getValue());
        assertTrue(message.getSignatureLength().getValue() == 70);
    }

    @Test(expected = PreparationException.class)
    public void testPrepareUnknownPrivateKey() throws NoSuchAlgorithmException {
        // DSA private key signing is not supported so it should throw a
        // preparation exception
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(1024, new BadRandom());
        KeyPair pair = generator.genKeyPair();
        context.getConfig().setPrivateKey(pair.getPrivate());
        preparator.prepare();
    }

}
