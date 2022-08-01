/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import org.apache.commons.lang.NullArgumentException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)

public class RecordAEADCipherTest {

    private TlsContext context;
    private RecordAEADCipher cipher;
    private Record record;
    private KeySet keySet;
    private final Mode mode;

    private final ProtocolVersion protocolVersion;
    private final byte[] explicitNonce;
    private final byte[] aeadSalt;
    private final byte[] gcmNonce;
    private final byte[] authenticationTag;
    private final byte[] authenticatedMetaData;
    private final byte[] authenticatedNonMetaData;
    private final byte[] cipherkey;
    private final byte[] plainRecordBytes;
    private final byte[] ciphertext;
    private final byte[] protocolMessageBytes;
    private final CipherSuite cipherSuite;
    private final byte[] random;
    private final byte[] iv;
    private final byte[] key;
    private final byte[] data;
    private final BigInteger sequenceNumber;

    private enum Mode {
        // Message from the client is encrypted / decrypted
        ENCRYPT_CLIENT,
        DECRYPT_CLIENT,
        // Message from the server is encrypted / decrypted
        ENCRYPT_SERVER,
        DECRYPT_SERVER

    }

    private void setContext(Mode mode, CipherSuite cipherSuite, ProtocolVersion protocolVersion, byte[] random) {

        if (null == mode) {
            throw new NullArgumentException("Mode needs to be set");
        }

        switch (mode) {
            case ENCRYPT_CLIENT:
            case DECRYPT_SERVER:
                context.setConnection(new OutboundConnection());
                break;
            case DECRYPT_CLIENT:
            case ENCRYPT_SERVER:
                context.setConnection(new InboundConnection());
        }

        context.setSelectedCipherSuite(cipherSuite);
        context.setSelectedProtocolVersion(protocolVersion);
        context.setRandom(new TestRandomData(random));

    }

    private void generateKeySet(Mode mode, byte[] key, byte[] iv) {

        switch (mode) {
            case DECRYPT_SERVER:
            case ENCRYPT_SERVER:
                keySet.setServerWriteKey(key);
                keySet.setServerWriteMacSecret(new byte[0]);
                keySet.setServerWriteIv(iv);

                keySet.setClientWriteIv(new byte[12]); // ClientSide is not used
                keySet.setClientWriteKey(new byte[16]); // ClientSide is not used
                keySet.setClientWriteMacSecret(new byte[0]); // ClientSide is not used
                break;
            case DECRYPT_CLIENT:
            case ENCRYPT_CLIENT:
                keySet.setClientWriteKey(key);
                keySet.setClientWriteMacSecret(new byte[0]);
                keySet.setClientWriteIv(iv);

                keySet.setServerWriteIv(new byte[12]); // ServerSide is not used
                keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
                keySet.setServerWriteMacSecret(new byte[0]); // ServerSide is not used
        }

    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {

        return Arrays.asList(new Object[][] {
            // Tests for TLS 1.2
            // TLS_RSA_WITH_AES_128_GCM_SHA256
            { Mode.ENCRYPT_CLIENT, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("FFEEDDCC"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                new BigInteger("0"), ArrayConverter.hexStringToByteArray("0000000000000000"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
                ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
                ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0") }

            ,
            { Mode.ENCRYPT_SERVER, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("FFEEDDCC"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                new BigInteger("0"), ArrayConverter.hexStringToByteArray("0000000000000000"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
                ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
                ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0") },
            { Mode.DECRYPT_CLIENT, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("FFEEDDCC"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
                new BigInteger("0"), ArrayConverter.hexStringToByteArray("0000000000000000"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
                ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
                ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0") },
            { Mode.DECRYPT_SERVER, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("FFEEDDCC"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
                new BigInteger("0"), ArrayConverter.hexStringToByteArray("0000000000000000"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
                ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
                ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                ArrayConverter.hexStringToByteArray(
                    "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                ArrayConverter.hexStringToByteArray(
                    "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0") },

            // Tests for TLS 1.3

            // Ciphersuite TLS_AES_128_CCM_SHA256
            // Test Data was used from
            // "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CCM.pdf"
            { Mode.ENCRYPT_CLIENT, CipherSuite.TLS_AES_128_CCM_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("60E12062EC2E1A6D828D8048ECBFD0E7"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7") },
            { Mode.ENCRYPT_SERVER, CipherSuite.TLS_AES_128_CCM_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("60E12062EC2E1A6D828D8048ECBFD0E7"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7") },
            { Mode.DECRYPT_CLIENT, CipherSuite.TLS_AES_128_CCM_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("60E12062EC2E1A6D828D8048ECBFD0E7"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7") },
            { Mode.DECRYPT_SERVER, CipherSuite.TLS_AES_128_CCM_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("60E12062EC2E1A6D828D8048ECBFD0E7"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray(
                    "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A60E12062EC2E1A6D828D8048ECBFD0E7") },

            // Ciphersuite TLS_AES_128_CCM_SHA256

            { Mode.ENCRYPT_SERVER, CipherSuite.TLS_AES_128_CCM_8_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("5C2F7623859ABBD3"),
                ArrayConverter.hexStringToByteArray("1703030021"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3") },
            { Mode.ENCRYPT_CLIENT, CipherSuite.TLS_AES_128_CCM_8_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("5C2F7623859ABBD3"),
                ArrayConverter.hexStringToByteArray("1703030021"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3") },
            { Mode.DECRYPT_SERVER, CipherSuite.TLS_AES_128_CCM_8_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("5C2F7623859ABBD3"),
                ArrayConverter.hexStringToByteArray("1703030021"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3") },
            { Mode.DECRYPT_CLIENT, CipherSuite.TLS_AES_128_CCM_8_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("1122334455667788"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("5C2F7623859ABBD3"),
                ArrayConverter.hexStringToByteArray("1703030021"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A"),
                ArrayConverter
                    .hexStringToByteArray("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA57A5C2F7623859ABBD3")

            },

            // Ciphersuite TLS_CHACHA20_POLY1305_SHA256

            { Mode.ENCRYPT_CLIENT, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("76CC64629BC0C69028083D74747AF636"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636") },
            { Mode.ENCRYPT_SERVER, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F3031323334353637"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("76CC64629BC0C69028083D74747AF636"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636") },
            { Mode.DECRYPT_CLIENT, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("76CC64629BC0C69028083D74747AF636"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636") },
            { Mode.DECRYPT_SERVER, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, ProtocolVersion.TLS13,
                ArrayConverter.hexStringToByteArray("404142434445464748494A4B4C4D4E4F"),
                ArrayConverter.hexStringToByteArray("10111213"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636"),
                new BigInteger("1447087143713839643"), ArrayConverter.hexStringToByteArray(""),
                ArrayConverter.hexStringToByteArray("10111213"),
                ArrayConverter.hexStringToByteArray("101112131415161718191A1B"),
                ArrayConverter.hexStringToByteArray("76CC64629BC0C69028083D74747AF636"),
                ArrayConverter.hexStringToByteArray("1703030029"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray("202122232425262728292A2B2C2D2E2F303132333435363716"),
                ArrayConverter.hexStringToByteArray("20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE5"),
                ArrayConverter.hexStringToByteArray(
                    "20F8A7B1DE3717873FD84E55F0F6F827D300F5D6BD72135BE576CC64629BC0C69028083D74747AF636") }

        });
    }

    public RecordAEADCipherTest(Mode mode, CipherSuite cipherSuite, ProtocolVersion protocolVersion, byte[] key,
        byte[] iv, byte[] random, byte[] data, BigInteger sequenceNumber, byte[] explicitNonce, byte[] aeadSalt,
        byte[] gcmNonce, byte[] authenticationTag, byte[] authenticatedMetaData, byte[] authenticatedNonMetaData,
        byte[] plainRecordBytes, byte[] ciphertext, byte[] protocolMsgBytes) {

        this.mode = mode;
        this.cipherSuite = cipherSuite;
        this.key = key;
        this.iv = iv;
        this.random = random;
        this.data = data;
        this.sequenceNumber = sequenceNumber;
        this.protocolVersion = protocolVersion;
        this.explicitNonce = explicitNonce;
        this.aeadSalt = aeadSalt;
        this.gcmNonce = gcmNonce;
        this.authenticationTag = authenticationTag;
        this.authenticatedMetaData = authenticatedMetaData;
        this.authenticatedNonMetaData = authenticatedNonMetaData;
        this.cipherkey = key;
        this.plainRecordBytes = plainRecordBytes;
        this.ciphertext = ciphertext;
        this.protocolMessageBytes = protocolMsgBytes;

    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
        this.context = new TlsContext();
        this.keySet = new KeySet();
        this.record = new Record();

        setContext(mode, cipherSuite, protocolVersion, random);
        generateKeySet(mode, key, iv);

        cipher = new RecordAEADCipher(context,
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), keySet,
                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));

        if (protocolVersion == ProtocolVersion.TLS12) {

            switch (mode) {
                case ENCRYPT_CLIENT:
                case ENCRYPT_SERVER:
                    record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
                    record.prepareComputations();
                    record.setSequenceNumber(sequenceNumber);
                    record.setCleanProtocolMessageBytes(data);
                    record.setProtocolVersion(ProtocolVersion.TLS12.getValue());

                    break;
                case DECRYPT_CLIENT:
                case DECRYPT_SERVER:
                    record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
                    record.prepareComputations();
                    record.setSequenceNumber(sequenceNumber);
                    record.setProtocolMessageBytes(data);
                    record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
            }

        } else {

            switch (mode) {
                case ENCRYPT_CLIENT:
                case ENCRYPT_SERVER:

                    record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
                    record.prepareComputations();
                    record.setSequenceNumber(sequenceNumber);
                    record.setCleanProtocolMessageBytes(data);
                    record.setProtocolVersion(ProtocolVersion.TLS12.getValue());

                    break;
                case DECRYPT_CLIENT:
                case DECRYPT_SERVER:

                    record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
                    record.setLength(data.length);
                    record.prepareComputations();
                    record.setSequenceNumber(sequenceNumber);
                    record.setProtocolMessageBytes(data);
                    record.setCleanProtocolMessageBytes(authenticatedNonMetaData);
                    record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
            }

        }

    }

    @Test
    public void testEncryptionDecryption() throws CryptoException {

        switch (mode) {
            case DECRYPT_SERVER:
            case DECRYPT_CLIENT:
                cipher.decrypt(record);
                break;
            case ENCRYPT_SERVER:
            case ENCRYPT_CLIENT:
                cipher.encrypt(record);
        }

        if (protocolVersion == ProtocolVersion.TLS12) {

            // These fields are not used within block ciphers
            assertNull(record.getComputations().getCbcInitialisationVector());
            assertNull(record.getComputations().getMacKey());
            assertNull(record.getComputations().getMac());
            assertNull(record.getComputations().getMacValid());
            assertNull(record.getComputations().getPaddingValid());
            assertNull(record.getComputations().getPadding());

            assertArrayEquals(explicitNonce, record.getComputations().getExplicitNonce().getValue());
            assertArrayEquals(aeadSalt, record.getComputations().getAeadSalt().getValue());
            assertArrayEquals(gcmNonce, record.getComputations().getGcmNonce().getValue());
            assertArrayEquals(authenticationTag, record.getComputations().getAuthenticationTag().getValue());
            assertTrue(record.getComputations().getAuthenticationTagValid());

            assertArrayEquals(authenticatedMetaData, record.getComputations().getAuthenticatedMetaData().getValue());
            assertArrayEquals(authenticatedNonMetaData,
                record.getComputations().getAuthenticatedNonMetaData().getValue());

            assertArrayEquals(cipherkey, record.getComputations().getCipherKey().getValue());
            assertArrayEquals(plainRecordBytes, record.getComputations().getPlainRecordBytes().getValue());
            assertArrayEquals(ciphertext, record.getComputations().getCiphertext().getValue());

            assertArrayEquals(protocolMessageBytes, record.getProtocolMessageBytes().getValue());

        } else {

            assertNull(record.getComputations().getCbcInitialisationVector());
            assertNull(record.getComputations().getMacKey());
            assertNull(record.getComputations().getMac());
            assertNull(record.getComputations().getMacValid());

            assertArrayEquals(ArrayConverter.hexStringToByteArray(""),
                record.getComputations().getPadding().getValue());
            assertNull(record.getComputations().getPaddingValid());

            assertArrayEquals(explicitNonce, record.getComputations().getExplicitNonce().getValue());
            assertArrayEquals(aeadSalt, record.getComputations().getAeadSalt().getValue());
            assertArrayEquals(gcmNonce, record.getComputations().getGcmNonce().getValue());
            assertArrayEquals(authenticationTag, record.getComputations().getAuthenticationTag().getValue());
            assertTrue(record.getComputations().getAuthenticationTagValid());

            assertArrayEquals(authenticatedMetaData, record.getComputations().getAuthenticatedMetaData().getValue());
            assertArrayEquals(authenticatedNonMetaData,
                record.getComputations().getAuthenticatedNonMetaData().getValue());

            assertArrayEquals(cipherkey, record.getComputations().getCipherKey().getValue());
            assertArrayEquals(plainRecordBytes, record.getComputations().getPlainRecordBytes().getValue());
            assertArrayEquals(ciphertext, record.getComputations().getCiphertext().getValue());
            assertArrayEquals(protocolMessageBytes, record.getProtocolMessageBytes().getValue());

        }

    }
}
