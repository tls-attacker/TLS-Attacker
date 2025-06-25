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

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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
        byte[] secret = new byte[48];
        String label = "master secret";
        byte[] seed = new byte[60];
        Random r = new Random();
        r.nextBytes(seed);
        int size = 48;

        byte[] result1 = PRF(new HMac(DigestFactory.createSHA256()), secret, label, seed, size);
        byte[] result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_SHA256, secret, label, seed, size);
        assertArrayEquals(result1, result2);

        result1 = PRF(new HMac(DigestFactory.createSHA384()), secret, label, seed, size);
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_SHA384, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        seed =
                DataConverter.hexStringToByteArray(
                        "DD65AFF37A86CD3BECFAF84BE5C85787009FCE23DED71B513EC6F97BA44CF654C6891E4146BBE9DE33DFE9936917C47ED8810D90DDFA90CBDFFAEAD7");
        result1 =
                DataConverter.hexStringToByteArray(
                        "49BC96FF7CB5A404DFBE1F06CFE49A01D728BDBCDA0FDD87F9B349FF9E2537959F2D0DB3C4480E2C1916D19C2FF5623D");
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_GOSTR3411, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        secret =
                DataConverter.hexStringToByteArray(
                        "0DA8674196F2496C4EE1E4779DE04990BE3CE4655252F1961E707B61178436131369D11E7DA84C05374535B95550DD0F");
        seed =
                DataConverter.hexStringToByteArray(
                        "52E78F4F4E131F8CABAFD5D7C9C62A5EDF62CADB4D033131FE9B83DE9D459EFD52E78F4F6AA0FE312217AEF691AD763932945E8CEDD7F96E3C336B0866A66698");
        result1 =
                DataConverter.hexStringToByteArray(
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

        byte[] result1 = PRF_legacy(secret, label, seed, size);

        byte[] result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);

        assertArrayEquals(result1, result2);

        String new_label = "extended master secret";

        result1 = PRF_legacy(secret, new_label, seed, size);

        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY, secret, new_label, seed, size);

        assertArrayEquals(result1, result2);
    }

    @Test
    public void testComputeForSSL3() throws NoSuchAlgorithmException, IOException {
        byte[] master_secret = DataConverter.hexStringToByteArray(StringUtils.repeat("01", 48));
        byte[] client_random = DataConverter.hexStringToByteArray(StringUtils.repeat("02", 32));
        byte[] server_random = DataConverter.hexStringToByteArray(StringUtils.repeat("03", 32));

        byte[] result1 =
                PseudoRandomFunction.computeSSL3(master_secret, client_random, server_random, 48);
        byte[] result2 =
                DataConverter.hexStringToByteArray(
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

        byte[] result1 = PRF_legacy(secret, label, seed, size);
        byte[] result2 = PseudoRandomFunction.compute(prfAlgorithm, secret, label, seed, size);
        assertArrayEquals(result1, result2);

        /*
         * Test case 2: test the whole keyBlock generation process check, if master secret is computed correctly
         */
        DHClientKeyExchangeMessage message = new DHClientKeyExchangeMessage();
        message.setPublicKey(new byte[] {1});
        message.prepareComputations();
        message.getComputations()
                .setPremasterSecret(
                        DataConverter.hexStringToByteArray(
                                "17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf"));
        message.getComputations()
                .setClientServerRandom(
                        DataConverter.hexStringToByteArray(
                                "c8c9c788adbd9dc72b5dd0635f9e2576e09c87b67e045c026ffa3281069601fd594c07e445947b545a746fcbc094e12427e0286be2199300925a81be02bf5467"));
        result1 =
                PRF_legacy(
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
                DataConverter.hexStringToByteArray(
                        "4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc");
        result1 = PRF_legacy(result1, "key expansion", serverClientRandom, 136);
        result2 =
                PseudoRandomFunction.compute(
                        PRFAlgorithm.TLS_PRF_LEGACY,
                        result2,
                        "key expansion",
                        serverClientRandom,
                        136);
        assertArrayEquals(result1, result2);
    }

    // The following PRF code is borrowed from BouncyCastle v1.80
    // Import required as the methods are private within the BouncyCastle library
    // Modified to accept raw values instead of TLSKeyMaterialSpec
    // https://github.com/bcgit/bc-java/blob/r1rv80/prov/src/main/java/org/bouncycastle/jcajce/provider/symmetric/TLSKDF.java

    private byte[] PRF(Mac prf, byte[] secret, String labelStr, byte[] seed, int size) {
        byte[] label = Strings.toByteArray(labelStr);
        byte[] labelSeed = Arrays.concatenate(label, seed);

        byte[] buf = new byte[size];

        hmac_hash(prf, secret, labelSeed, buf);

        return buf;
    }

    private static byte[] PRF_legacy(byte[] secret, String labelStr, byte[] seed, int size) {
        Mac md5Hmac = new HMac(DigestFactory.createMD5());
        Mac sha1HMac = new HMac(DigestFactory.createSHA1());

        byte[] label = Strings.toByteArray(labelStr);
        byte[] labelSeed = Arrays.concatenate(label, seed);

        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];

        hmac_hash(md5Hmac, s1, labelSeed, b1);
        hmac_hash(sha1HMac, s2, labelSeed, b2);

        for (int i = 0; i < size; i++) {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    private static void hmac_hash(Mac mac, byte[] secret, byte[] seed, byte[] out) {
        mac.init(new KeyParameter(secret));
        byte[] a = seed;
        int size = mac.getMacSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++) {
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }
}
