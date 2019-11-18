/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.MD5Utils;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeySetGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static KeySet generateKeySet(TlsContext context, ProtocolVersion protocolVersion, Tls13KeySetType keySetType)
            throws NoSuchAlgorithmException, CryptoException {
        if (protocolVersion.isTLS13()) {
            return getTls13KeySet(context, keySetType);
        } else {
            return getTlsKeySet(context);
        }

    }

    public static KeySet generateKeySet(TlsContext context) throws NoSuchAlgorithmException, CryptoException {
        return generateKeySet(context, context.getChooser().getSelectedProtocolVersion(),
                context.getActiveKeySetTypeWrite());
    }

    private static KeySet getTls13KeySet(TlsContext context, Tls13KeySetType keySetType) throws CryptoException {
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        byte[] clientSecret = new byte[0];
        byte[] serverSecret = new byte[0];
        if (null == keySetType) {
            throw new CryptoException("Unknown KeySetType:" + keySetType.name());
        } else {
            switch (keySetType) {
                case HANDSHAKE_TRAFFIC_SECRETS:
                    clientSecret = context.getChooser().getClientHandshakeTrafficSecret();
                    serverSecret = context.getChooser().getServerHandshakeTrafficSecret();
                    break;
                case APPLICATION_TRAFFIC_SECRETS:
                    clientSecret = context.getChooser().getClientApplicationTrafficSecret();
                    serverSecret = context.getChooser().getServerApplicationTrafficSecret();
                    break;
                case EARLY_TRAFFIC_SECRETS:
                    cipherSuite = context.getChooser().getEarlyDataCipherSuite();
                    clientSecret = context.getChooser().getClientEarlyTrafficSecret();
                    serverSecret = context.getChooser().getClientEarlyTrafficSecret();
                    break;
                case NONE:
                    LOGGER.warn("KeySet is NONE! , returning empty KeySet");
                    return new KeySet(keySetType);
                default:
                    throw new CryptoException("Unknown KeySetType:" + keySetType.name());
            }
        }
        LOGGER.debug("ActiveKeySetType is " + keySetType);
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        KeySet keySet = new KeySet(keySetType);
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        keySet.setClientWriteKey(HKDFunction.expandLabel(hkdfAlgortihm, clientSecret, HKDFunction.KEY, new byte[] {},
                cipherAlg.getKeySize()));
        LOGGER.debug("Client write key: {}", ArrayConverter.bytesToHexString(keySet.getClientWriteKey()));
        keySet.setServerWriteKey(HKDFunction.expandLabel(hkdfAlgortihm, serverSecret, HKDFunction.KEY, new byte[] {},
                cipherAlg.getKeySize()));
        LOGGER.debug("Server write key: {}", ArrayConverter.bytesToHexString(keySet.getServerWriteKey()));
        keySet.setClientWriteIv(HKDFunction.expandLabel(hkdfAlgortihm, clientSecret, HKDFunction.IV, new byte[] {},
                RecordAEADCipher.AEAD_IV_LENGTH));
        LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(keySet.getClientWriteIv()));
        keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm, serverSecret, HKDFunction.IV, new byte[] {},
                RecordAEADCipher.AEAD_IV_LENGTH));
        LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(keySet.getServerWriteIv()));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setClientWriteMacSecret(new byte[0]);
        return keySet;
    }

    private static KeySet getTlsKeySet(TlsContext context) throws CryptoException {
        ProtocolVersion protocolVersion = context.getChooser().getSelectedProtocolVersion();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        byte[] masterSecret = context.getChooser().getMasterSecret();
        byte[] seed = ArrayConverter.concatenate(context.getChooser().getServerRandom(), context.getChooser()
                .getClientRandom());

        byte[] keyBlock;
        if (protocolVersion.isSSL()) {
            keyBlock = SSLUtils.calculateKeyBlockSSL3(masterSecret, seed,
                    getSecretSetSize(protocolVersion, cipherSuite));
        } else {
            PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(protocolVersion, cipherSuite);
            keyBlock = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
                    PseudoRandomFunction.KEY_EXPANSION_LABEL, seed, getSecretSetSize(protocolVersion, cipherSuite));
        }
        LOGGER.debug("A new key block was generated: {}", ArrayConverter.bytesToHexString(keyBlock));
        KeyBlockParser parser = new KeyBlockParser(keyBlock, cipherSuite, protocolVersion);
        KeySet keySet = parser.parse();
        if (cipherSuite.isExportSymmetricCipher()) {
            deriveExportKeys(keySet, context);
        }
        return keySet;
    }

    private static void deriveExportKeys(KeySet keySet, TlsContext context) throws CryptoException {
        ProtocolVersion protocolVersion = context.getChooser().getSelectedProtocolVersion();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        byte[] clientRandom = context.getChooser().getClientRandom();
        byte[] serverRandom = context.getChooser().getServerRandom();

        if (protocolVersion == ProtocolVersion.SSL3) {
            deriveSSL3ExportKeys(cipherSuite, keySet, clientRandom, serverRandom);
            return;
        }

        byte[] clientAndServerRandom = ArrayConverter.concatenate(clientRandom, serverRandom);
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(protocolVersion, cipherSuite);
        int keySize = AlgorithmResolver.getCipher(cipherSuite).getKeySize();

        keySet.setClientWriteKey(PseudoRandomFunction.compute(prfAlgorithm, keySet.getClientWriteKey(),
                PseudoRandomFunction.CLIENT_WRITE_KEY_LABEL, clientAndServerRandom, keySize));
        keySet.setServerWriteKey(PseudoRandomFunction.compute(prfAlgorithm, keySet.getServerWriteKey(),
                PseudoRandomFunction.SERVER_WRITE_KEY_LABEL, clientAndServerRandom, keySize));

        int blockSize = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
        byte[] emptySecret = {};
        byte[] ivBlock = PseudoRandomFunction.compute(prfAlgorithm, emptySecret, PseudoRandomFunction.IV_BLOCK_LABEL,
                clientAndServerRandom, 2 * blockSize);
        keySet.setClientWriteIv(Arrays.copyOfRange(ivBlock, 0, blockSize));
        keySet.setServerWriteIv(Arrays.copyOfRange(ivBlock, blockSize, 2 * blockSize));
    }

    private static byte[] MD5firstNBytes(int numOfBytes, byte[]... byteArrays) {
        byte[] md5 = MD5Utils.MD5(byteArrays);
        return Arrays.copyOfRange(md5, 0, numOfBytes);
    }

    private static void deriveSSL3ExportKeys(CipherSuite cipherSuite, KeySet keySet, byte[] clientRandom,
            byte[] serverRandom) {
        int keySize = AlgorithmResolver.getCipher(cipherSuite).getKeySize();
        keySet.setClientWriteKey(MD5firstNBytes(keySize, keySet.getClientWriteKey(), clientRandom, serverRandom));
        keySet.setServerWriteKey(MD5firstNBytes(keySize, keySet.getServerWriteKey(), serverRandom, clientRandom));

        int blockSize = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
        keySet.setClientWriteIv(MD5firstNBytes(blockSize, clientRandom, serverRandom));
        keySet.setServerWriteIv(MD5firstNBytes(blockSize, serverRandom, clientRandom));
    }

    private static int getSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite)
            throws CryptoException {
        switch (AlgorithmResolver.getCipherType(cipherSuite)) {
            case AEAD:
                return getAeadSecretSetSize(protocolVersion, cipherSuite);
            case BLOCK:
                return getBlockSecretSetSize(protocolVersion, cipherSuite);
            case STREAM:
                return getStreamSecretSetSize(protocolVersion, cipherSuite);
            default:
                throw new CryptoException("Unknown CipherType");
        }
    }

    private static int getBlockSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        int keySize = cipherAlg.getKeySize();
        MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(protocolVersion, cipherSuite);
        int secretSetSize = (2 * keySize) + (2 * macAlg.getKeySize());
        if (!protocolVersion.usesExplicitIv()) {
            secretSetSize += (2 * cipherAlg.getNonceBytesFromHandshake());
        }
        return secretSetSize;
    }

    private static int getAeadSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        int keySize = cipherAlg.getKeySize();
        int saltSize = RecordAEADCipher.AEAD_IV_LENGTH - cipherAlg.getNonceBytesFromRecord();
        int secretSetSize = 2 * keySize + 2 * saltSize;
        return secretSetSize;
    }

    private static int getStreamSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(protocolVersion, cipherSuite);
        int secretSetSize = (2 * cipherAlg.getKeySize()) + (2 * macAlg.getKeySize());
        if (cipherSuite.isSteamCipherWithIV()) {
            secretSetSize += (2 * cipherAlg.getNonceBytesFromHandshake());
        }
        return secretSetSize;
    }

    private KeySetGenerator() {
    }
}
