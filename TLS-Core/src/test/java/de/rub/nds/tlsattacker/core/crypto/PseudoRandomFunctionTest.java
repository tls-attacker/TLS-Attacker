/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PseudoRandomFunctionTest {

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     *
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testComputeForTls12() throws CryptoException {
        TlsContext mockedTlsContext = mock(TlsContext.class);
        SecurityParameters mockedParameters = mock(SecurityParameters.class);
        // Stub method calls
        when(mockedTlsContext.getServerVersion()).thenReturn(ProtocolVersion.TLSv12);
        when(mockedTlsContext.getSecurityParameters()).thenReturn(mockedParameters);
        when(mockedParameters.getPrfAlgorithm()).thenReturn(1);

        byte[] secret = new byte[48];
        String label = "master secret";
        byte[] seed = new byte[60];
        Random r = new Random();
        r.nextBytes(seed);
        int size = 48;

        byte[] result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
        byte[] result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_SHA256, secret, label, seed, size);
        assertArrayEquals(result1, result2);

        // Stub method calls
        when(mockedParameters.getPrfAlgorithm()).thenReturn(2);

        result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_SHA384, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        seed =
                ArrayConverter.hexStringToByteArray(
                        "DD65AFF37A86CD3BECFAF84BE5C85787009FCE23DED71B513EC6F97BA44CF654C6891E4146BBE9DE33DFE9936917C47ED8810D90DDFA90CBDFFAEAD7");
        result1 =
                ArrayConverter.hexStringToByteArray(
                        "49BC96FF7CB5A404DFBE1F06CFE49A01D728BDBCDA0FDD87F9B349FF9E2537959F2D0DB3C4480E2C1916D19C2FF5623D");
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_GOSTR3411, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        secret =
                ArrayConverter.hexStringToByteArray(
                        "0DA8674196F2496C4EE1E4779DE04990BE3CE4655252F1961E707B61178436131369D11E7DA84C05374535B95550DD0F");
        seed =
                ArrayConverter.hexStringToByteArray(
                        "52E78F4F4E131F8CABAFD5D7C9C62A5EDF62CADB4D033131FE9B83DE9D459EFD52E78F4F6AA0FE312217AEF691AD763932945E8CEDD7F96E3C336B0866A66698");
        result1 =
                ArrayConverter.hexStringToByteArray(
                        "6622B653451DBB85BA0494959A6255F02100B93FCF09AF94176A3CA6E7FD09DCDA0357FE5AF3110EBC7B2466B66AB37E");
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_GOSTR3411_2012_256, secret, label, seed, size);

        assertArrayEquals(result1, result2);
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     *
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testComputeForTls11() throws CryptoException {
        byte[] secret = new byte[48];
        String label = "master secret";
        byte[] seed = new byte[60];
        Random r = new Random();
        r.nextBytes(seed);
        int size = 48;

        byte[] result1 = TlsUtils.PRF_legacy(secret, label, seed, size);

        byte[] result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        String new_label = "extended master secret";

        result1 = TlsUtils.PRF_legacy(secret, new_label, seed, size);

        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY, secret, new_label, seed, size);

        assertArrayEquals(result1, result2);
    }

    @Test
    public void testComputeForSSL3() throws NoSuchAlgorithmException, IOException {
        byte[] master_secret = ArrayConverter.hexStringToByteArray(StringUtils.repeat("01", 48));
        byte[] client_random = ArrayConverter.hexStringToByteArray(StringUtils.repeat("02", 32));
        byte[] server_random = ArrayConverter.hexStringToByteArray(StringUtils.repeat("03", 32));

        byte[] result1 =
                PseudoRandomFunction.computeSSL3(master_secret, client_random, server_random, 48);
        byte[] result2 =
                ArrayConverter.hexStringToByteArray(
                        "24d8e8797e3a106b7752b22cbf8829acf27c8f1e2630e9c2d3442f991e7736288d696027c06fd118f1c59311a66039a0");

        assertArrayEquals(result1, result2);
    }

    @Test
    public void testComputeForTLS10() throws CryptoException {
        /*
         * Test case 1: secret with length 0
         */
        byte[] secret = new byte[0];
        PRFAlgorithm prfAlgorithm = PRFAlgorithm.TLS_PRF_LEGACY;
        String label = "master secret";
        byte[] seed = new byte[60];
        int size = 48;

        byte[] result1 = TlsUtils.PRF_legacy(secret, label, seed, size);
        byte[] result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);
        assertArrayEquals(result1, result2);

        /*
         * Test case 2: test the whole keyBlock generation process check, if master secret is computed correctly
         */
        DHClientKeyExchangeMessage message = new DHClientKeyExchangeMessage();
        message.setPublicKey(new byte[] {1});
        message.prepareComputations();
        message.getComputations()
                .setPremasterSecret(
                        ArrayConverter.hexStringToByteArray(
                                "17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf"));
        message.getComputations()
                .setClientServerRandom(
                        ArrayConverter.hexStringToByteArray(
                                "c8c9c788adbd9dc72b5dd0635f9e2576e09c87b67e045c026ffa3281069601fd594c07e445947b545a746fcbc094e12427e0286be2199300925a81be02bf5467"));
        result1 =
                TlsUtils.PRF_legacy(
                        message.getComputations().getPremasterSecret().getValue(),
                        label,
                        message.getComputations().getClientServerRandom().getValue(),
                        size);
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY,
                        message.getComputations().getPremasterSecret().getValue(),
                        label,
                        message.getComputations().getClientServerRandom().getValue(),
                        size);
        assertArrayEquals(result1, result2);

        /*
         * check, if keyblock is computed correctly TLS_DHE_RSA_WITH_AES_256_CBC_SHA MAC Write Client 20 Bytes Mac Write
         * Server 20 Bytes Enc Write Client 32 Bytes Enc Write Server 32 Bytes IV Write Client 16 Bytes IV Write Server
         * 16 Bytes
         */
        byte[] serverClientRandom =
                ArrayConverter.hexStringToByteArray(
                        "4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc");
        result1 = TlsUtils.PRF_legacy(result1, "key expansion", serverClientRandom, 136);
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY,
                        result2,
                        "key expansion",
                        serverClientRandom,
                        136);
        assertArrayEquals(result1, result2);
    }
}
