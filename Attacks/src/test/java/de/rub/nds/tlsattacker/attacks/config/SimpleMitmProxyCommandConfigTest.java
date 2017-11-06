/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.io.InputStream;
import org.junit.Test;


public class SimpleMitmProxyCommandConfigTest {

    private SimpleMitmProxyCommandConfig cmdConfig;
    private InputStream inputKeyStream;

    public SimpleMitmProxyCommandConfigTest() {
        cmdConfig = new SimpleMitmProxyCommandConfig(new GeneralDelegate());
    }

    // @Test
    // public void testLoadPrivateKeyRsa() {
    // inputKeyStream =
    // SimpleMitmProxyCommandConfig.class.getResourceAsStream("/rsa1024.key");
    // System.out.println(inputKeyStream);
    // InputStreamReader keyStream = new InputStreamReader(inputKeyStream);
    // PrivateKey privKey = cmdConfig.getPrivateKey(keyStream);
    //
    // assertEquals(privKey.getFormat(), "PKCS#8");
    // assertEquals(privKey.getAlgorithm(), "RSA");
    // assertTrue(privKey instanceof BCRSAPrivateCrtKey);
    // }
    //
    // @Test
    // public void testCreateConfigRsaKey() {
    // inputKeyStream =
    // SimpleMitmProxyCommandConfig.class.getResourceAsStream("/rsa1024.key");
    // System.out.println(inputKeyStream);
    // InputStreamReader keyStream = new InputStreamReader(inputKeyStream);
    //
    // cmdConfig.keyStream = keyStream;
    // Config config = cmdConfig.createConfig();
    // assertEquals(
    // config.getDefaultRSAModulus(),
    // new BigInteger(
    // 1,
    // ArrayConverter
    // .hexStringToByteArray("c4c4f8f259f5ac2016120a7663e406d8c1c37fcbd02638e65a57e4d986abb48098a926a45c9195269c21a89207f8db5972564008d03d66b8a061a04e0b9434a77c42601f43a35466d384d82a83342f07cabbf3b29ab638ef35cf547ceec3add729145da7166e13bf3a0aa71d77b5e73942f6f100c91e8d38ff9d27d05960b619")));
    // assertEquals(
    // config.getDefaultServerRSAPrivateKey(),
    // new BigInteger(
    // 1,
    // ArrayConverter
    // .hexStringToByteArray("148647416048d3ef74dde4e17c81e884eb912cdf6192db148c0fe6fb19a5076af281925a4a9d94e5361bfcad5ecf8271ce0f591692421558e4c1ca2ad9e257ab81e15183053e74082db7cd1a05dfb84b8ad245313c2938898cd51b04761b38f38b8e7a500221d8b76952d8357ce030e841922618b0d4fedd8d2d5708cd029401")));
    // assertEquals(config.getDefaultServerRSAPublicKey(),
    // new BigInteger(1, ArrayConverter.hexStringToByteArray("010001")));
    // }

    @Test
    public void testLoadPrivateKeyRsaWithPassword() {
    }

    @Test
    public void testLoadPrivateKeyEc() {
    }

    @Test
    public void testLoadPrivateKeyEcWithPassword() {
    }

    @Test
    public void testLoadPrivateKeyDh() {
    }

    @Test
    public void testLoadPrivateKeyDhWithPassword() {
    }

}
