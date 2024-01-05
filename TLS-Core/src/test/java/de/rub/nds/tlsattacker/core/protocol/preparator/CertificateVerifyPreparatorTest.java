/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.concatenate;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class CertificateVerifyPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                CertificateVerifyMessage, CertificateVerifyPreparator> {

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CertificateVerifyPreparatorTest() {
        super(CertificateVerifyMessage::new, CertificateVerifyPreparator::new);
    }

    private static byte[] repeatBytes(String hex, int count) {
        return ArrayConverter.hexStringToByteArray(StringUtils.repeat(hex, count));
    }

    /**
     * Test for correct generation of CertificateVerify.signature for SSLv3 with empty secret and no
     * handshake_messages. From RFC 6101:
     *
     * <p>5.6.8. Certificate Verify
     *
     * <p>This message is used to provide explicit verification of a client certificate. This
     * message is only sent following any client certificate that has signing capability (i.e., all
     * certificates except those containing fixed Diffie-Hellman parameters).
     *
     * <p>struct { Signature signature; } CertificateVerify;
     *
     * <p>CertificateVerify.signature.md5_hash MD5(master_secret + pad_2 + MD5(handshake_messages +
     * master_secret + pad_1)); Certificate.signature.sha_hash SHA(master_secret + pad_2 +
     * SHA(handshake_messages + master_secret + pad_1));
     *
     * <p>pad_1: This is identical to the pad_1 defined in Section 5.2.3.1.
     *
     * <p>pad_2: This is identical to the pad_2 defined in Section 5.2.3.1.
     *
     * <p>Here, handshake_messages refers to all handshake messages starting at client hello up to
     * but not including this message.
     *
     * <p>.......
     *
     * <p>pad_1: The character 0x36 repeated 48 times for MD5 or 40 times for SHA.
     *
     * <p>pad_2: The character 0x5c repeated 48 times for MD5 or 40 times for SHA.
     *
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testPrepareSSL3RSA() throws NoSuchAlgorithmException {
        context.setMasterSecret(new byte[] {});
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        assertEquals(0, context.getDigest().getRawBytes().length);
        assertEquals(0, context.getMasterSecret().length);
        preparator.prepare();

        final MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
        final MessageDigest sha = java.security.MessageDigest.getInstance("SHA-1");
        final byte[] innerMD5 = md5.digest(repeatBytes("36", 48));
        final byte[] innerSHA = sha.digest(repeatBytes("36", 40));
        final byte[] outerMD5 = md5.digest(concatenate(repeatBytes("5c", 48), innerMD5));
        final byte[] outerSHA = sha.digest(concatenate(repeatBytes("5c", 40), innerSHA));
        final byte[] verify = concatenate(outerMD5, outerSHA);

        assertArrayEquals(verify, message.getSignature().getValue());
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class CertificateVerifyPreparator.
     *
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    @Disabled("To be fixed")
    public void testPrepare() throws NoSuchAlgorithmException {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ECDSA_NONE);
        algoList.add(SignatureAndHashAlgorithm.RSA_MD5);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        algoList.add(SignatureAndHashAlgorithm.RSA_SHA1);
        context.getConfig().setDefaultClientSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();
        assertArrayEquals(
                new byte[] {
                    1, 1,
                },
                message.getSignatureHashAlgorithm().getValue());
        // TODO I don't check if the signature is correctly calculated or
        // calculated over the correct values
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "479FB09700E855666B1D65C9C5B0D279088A0573A7FDA4F59E5816E7869CA7753F7648143F9A7DB86534D33EEA9ED40BB8FE052F5BAF1D9BE52502B57B6B5661F9A4DC077D4AC0714F5768D7319C6E3862BD6EFA2F85E464B54E8A89FC19FD2090E53DA05D5556E74A7EE31CD217A510620BD61F24F5CDFEF5ACDFE060B9F37E"),
                message.getSignature().getValue());
        assertEquals(128, (int) message.getSignatureLength().getValue());
    }

    @Test
    @Disabled("To be fixed")
    public void testPrepareEC() {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.ECDSA_NONE);
        algoList.add(SignatureAndHashAlgorithm.RSA_MD5);
        algoList.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        algoList.add(SignatureAndHashAlgorithm.RSA_SHA1);
        context.getConfig().setDefaultClientSupportedSignatureAndHashAlgorithms(algoList);
        preparator.prepare();

        assertArrayEquals(new byte[] {2, 3}, message.getSignatureHashAlgorithm().getValue());
        assertEquals(70, (int) message.getSignatureLength().getValue());
    }
}
