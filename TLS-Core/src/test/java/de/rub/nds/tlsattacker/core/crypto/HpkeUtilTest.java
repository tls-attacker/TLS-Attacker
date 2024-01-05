/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyEncapsulationMechanism;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeReceiverContext;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeSenderContext;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.math.BigInteger;
import org.junit.Assert;
import org.junit.Test;

public class HpkeUtilTest {

    // Test A.1.1. from RFC 9180
    @Test
    public void setupBaseSenderTest() throws CryptoException {
        HpkeKeyEncapsulationMechanism keyEncapsulationMechanism =
                HpkeKeyEncapsulationMechanism.getEnumByByte(new byte[] {0x20});
        HpkeKeyDerivationFunction keyDerivationFunction =
                HpkeKeyDerivationFunction.getEnumByByte(new byte[] {0x01});
        HpkeAeadFunction aeadFunction = HpkeAeadFunction.getEnumByByte(new byte[] {0x01});

        byte[] info =
                ArrayConverter.hexStringToByteArray("4f6465206f6e2061204772656369616e2055726e");
        byte[] echPublicKey =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        BigInteger privateKeySender =
                new BigInteger(
                        ArrayConverter.hexStringToByteArray(
                                "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"));
        byte[] publicKeySender =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        HpkeUtil hpkeUtil =
                new HpkeUtil(aeadFunction, keyDerivationFunction, keyEncapsulationMechanism);

        // create sender key
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setPrivateKey(privateKeySender);
        keyShareEntry.setPublicKey(publicKeySender);

        hpkeUtil.setupBaseSender(echPublicKey, info, keyShareEntry);

        byte[] expectedSharedSecret =
                ArrayConverter.hexStringToByteArray(
                        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        byte[] actualSharedSecret = hpkeUtil.getSharedSecret();

        byte[] expectedEnc =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        byte[] actualEnc = hpkeUtil.getPublicKeySender();

        byte[] expectedPublicKeyReceiver =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        byte[] actualPublicKeyReceiver = hpkeUtil.getPublicKeyReceiver();

        byte[] expectedKeyScheduleContext =
                ArrayConverter.hexStringToByteArray(
                        "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
        byte[] actualKeyScheduleContext = hpkeUtil.getKeyScheduleContext();

        byte[] expectedSecret =
                ArrayConverter.hexStringToByteArray(
                        "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        byte[] actualSecret = hpkeUtil.getSecret();

        byte[] expectedKey =
                ArrayConverter.hexStringToByteArray("4531685d41d65f03dc48f6b8302c05b0");
        byte[] actualKey = hpkeUtil.getKey();

        byte[] expectedBaseNonce = ArrayConverter.hexStringToByteArray("56d890e5accaaf011cff4b7d");
        byte[] actualBaseNonce = hpkeUtil.getBaseNonce();

        byte[] expectedExporterSecret =
                ArrayConverter.hexStringToByteArray(
                        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
        byte[] actualExporterSecret = hpkeUtil.getExporterSecret();

        Assert.assertArrayEquals(expectedEnc, actualEnc);
        Assert.assertArrayEquals(expectedPublicKeyReceiver, actualPublicKeyReceiver);
        Assert.assertArrayEquals(expectedSharedSecret, actualSharedSecret);
        Assert.assertArrayEquals(expectedKeyScheduleContext, actualKeyScheduleContext);
        Assert.assertArrayEquals(expectedSharedSecret, actualSharedSecret);
        Assert.assertArrayEquals(expectedPublicKeyReceiver, actualPublicKeyReceiver);
        Assert.assertArrayEquals(expectedSecret, actualSecret);
        Assert.assertArrayEquals(expectedKey, actualKey);
        Assert.assertArrayEquals(expectedBaseNonce, actualBaseNonce);
        Assert.assertArrayEquals(expectedExporterSecret, actualExporterSecret);
    }

    // Test A.1.1. from RFC 9180
    @Test
    public void setupBaseReceiverTest() throws CryptoException {
        HpkeKeyEncapsulationMechanism keyEncapsulationMechanism =
                HpkeKeyEncapsulationMechanism.getEnumByByte(new byte[] {0x20});
        HpkeKeyDerivationFunction keyDerivationFunction =
                HpkeKeyDerivationFunction.getEnumByByte(new byte[] {0x01});
        HpkeAeadFunction aeadFunction = HpkeAeadFunction.getEnumByByte(new byte[] {0x01});

        byte[] info =
                ArrayConverter.hexStringToByteArray("4f6465206f6e2061204772656369616e2055726e");

        byte[] publicKeyReceiver =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        BigInteger privateKeyReceiver =
                new BigInteger(
                        ArrayConverter.hexStringToByteArray(
                                "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"));
        byte[] enc =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        HpkeUtil hpkeUtil =
                new HpkeUtil(aeadFunction, keyDerivationFunction, keyEncapsulationMechanism);

        // create receiver key
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setPrivateKey(privateKeyReceiver);
        keyShareEntry.setPublicKey(publicKeyReceiver);

        hpkeUtil.setupBaseReceiver(enc, info, keyShareEntry);

        byte[] expectedSharedSecret =
                ArrayConverter.hexStringToByteArray(
                        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        byte[] actualSharedSecret = hpkeUtil.getSharedSecret();

        byte[] expectedEnc =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        byte[] actualEnc = hpkeUtil.getPublicKeySender();

        byte[] expectedPublicKeyReceiver =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        byte[] actualPublicKeyReceiver = hpkeUtil.getPublicKeyReceiver();

        byte[] expectedKeyScheduleContext =
                ArrayConverter.hexStringToByteArray(
                        "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
        byte[] actualKeyScheduleContext = hpkeUtil.getKeyScheduleContext();

        byte[] expectedSecret =
                ArrayConverter.hexStringToByteArray(
                        "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        byte[] actualSecret = hpkeUtil.getSecret();

        byte[] expectedKey =
                ArrayConverter.hexStringToByteArray("4531685d41d65f03dc48f6b8302c05b0");
        byte[] actualKey = hpkeUtil.getKey();

        byte[] expectedBaseNonce = ArrayConverter.hexStringToByteArray("56d890e5accaaf011cff4b7d");
        byte[] actualBaseNonce = hpkeUtil.getBaseNonce();

        byte[] expectedExporterSecret =
                ArrayConverter.hexStringToByteArray(
                        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
        byte[] actualExporterSecret = hpkeUtil.getExporterSecret();

        Assert.assertArrayEquals(expectedEnc, actualEnc);
        Assert.assertArrayEquals(expectedPublicKeyReceiver, actualPublicKeyReceiver);
        Assert.assertArrayEquals(expectedSharedSecret, actualSharedSecret);
        Assert.assertArrayEquals(expectedKeyScheduleContext, actualKeyScheduleContext);
        Assert.assertArrayEquals(expectedSharedSecret, actualSharedSecret);
        Assert.assertArrayEquals(expectedPublicKeyReceiver, actualPublicKeyReceiver);
        Assert.assertArrayEquals(expectedSecret, actualSecret);
        Assert.assertArrayEquals(expectedKey, actualKey);
        Assert.assertArrayEquals(expectedBaseNonce, actualBaseNonce);
        Assert.assertArrayEquals(expectedExporterSecret, actualExporterSecret);
    }

    // Test A.1.1. from RFC 9180
    @Test
    public void sealTest() throws CryptoException {
        HpkeKeyEncapsulationMechanism keyEncapsulationMechanism =
                HpkeKeyEncapsulationMechanism.getEnumByByte(new byte[] {0x20});
        HpkeKeyDerivationFunction keyDerivationFunction =
                HpkeKeyDerivationFunction.getEnumByByte(new byte[] {0x01});
        HpkeAeadFunction aeadFunction = HpkeAeadFunction.getEnumByByte(new byte[] {0x01});

        byte[] info =
                ArrayConverter.hexStringToByteArray("4f6465206f6e2061204772656369616e2055726e");

        byte[] echPublicKey =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        BigInteger privateKeySender =
                new BigInteger(
                        ArrayConverter.hexStringToByteArray(
                                "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"));
        byte[] publicKeySender =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        byte[] plaintext =
                ArrayConverter.hexStringToByteArray(
                        "4265617574792069732074727574682c20747275746820626561757479");
        byte[] aad = ArrayConverter.hexStringToByteArray("436f756e742d30");
        byte[] nonce = ArrayConverter.hexStringToByteArray("56d890e5accaaf011cff4b7d");

        HpkeUtil hpkeUtil =
                new HpkeUtil(aeadFunction, keyDerivationFunction, keyEncapsulationMechanism);

        // create own key
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setPrivateKey(privateKeySender);
        keyShareEntry.setPublicKey(publicKeySender);

        HpkeSenderContext hpkeSenderContext =
                hpkeUtil.setupBaseSender(echPublicKey, info, keyShareEntry);

        byte[] expectedCiphertext =
                ArrayConverter.hexStringToByteArray(
                        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
        byte[] actualCiphertext = hpkeSenderContext.seal(aad, plaintext, nonce);

        Assert.assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    // Test A.1.1. from RFC 9180
    @Test
    public void openTest() throws CryptoException {
        HpkeKeyEncapsulationMechanism keyEncapsulationMechanism =
                HpkeKeyEncapsulationMechanism.getEnumByByte(new byte[] {0x20});
        HpkeKeyDerivationFunction keyDerivationFunction =
                HpkeKeyDerivationFunction.getEnumByByte(new byte[] {0x01});
        HpkeAeadFunction aeadFunction = HpkeAeadFunction.getEnumByByte(new byte[] {0x01});

        byte[] info =
                ArrayConverter.hexStringToByteArray("4f6465206f6e2061204772656369616e2055726e");

        byte[] publicKeyReceiver =
                ArrayConverter.hexStringToByteArray(
                        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        BigInteger privateKeyReceiver =
                new BigInteger(
                        ArrayConverter.hexStringToByteArray(
                                "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"));
        byte[] enc =
                ArrayConverter.hexStringToByteArray(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        byte[] ciphertext =
                ArrayConverter.hexStringToByteArray(
                        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
        byte[] aad = ArrayConverter.hexStringToByteArray("436f756e742d30");
        byte[] nonce = ArrayConverter.hexStringToByteArray("56d890e5accaaf011cff4b7d");

        HpkeUtil hpkeUtil =
                new HpkeUtil(aeadFunction, keyDerivationFunction, keyEncapsulationMechanism);

        // create receiver key
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setPrivateKey(privateKeyReceiver);
        keyShareEntry.setPublicKey(publicKeyReceiver);

        HpkeReceiverContext hpkeReceiverContext =
                hpkeUtil.setupBaseReceiver(enc, info, keyShareEntry);

        byte[] expectedPlaintext =
                ArrayConverter.hexStringToByteArray(
                        "4265617574792069732074727574682c20747275746820626561757479");
        byte[] actualPlaintext = hpkeReceiverContext.open(aad, ciphertext, nonce);

        Assert.assertArrayEquals(expectedPlaintext, actualPlaintext);
    }
}
