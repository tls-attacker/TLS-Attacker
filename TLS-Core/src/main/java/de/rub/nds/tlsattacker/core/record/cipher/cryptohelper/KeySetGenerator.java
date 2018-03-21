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
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeySetGenerator {

    protected static final Logger LOGGER = LogManager.getLogger(KeySetGenerator.class.getName());

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
        if (keySetType == Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS) {
            clientSecret = context.getChooser().getClientHandshakeTrafficSecret();
            serverSecret = context.getChooser().getServerHandshakeTrafficSecret();
        } else if (keySetType == Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS) {
            clientSecret = context.getChooser().getClientApplicationTrafficSecret();
            serverSecret = context.getChooser().getServerApplicationTrafficSecret();
        } else if (keySetType == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            cipherSuite = context.getChooser().getEarlyDataCipherSuite();
            clientSecret = context.getChooser().getClientEarlyTrafficSecret();
            serverSecret = context.getChooser().getClientEarlyTrafficSecret();
        } else if (keySetType == Tls13KeySetType.NONE) {
            LOGGER.warn("KeySet is NONE! , returning empty KeySet");
            return new KeySet(keySetType);
        } else {
            throw new CryptoException("Unknown KeySetType:" + keySetType.name());
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
                RecordAEADCipher.GCM_IV_LENGTH));
        LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(keySet.getClientWriteIv()));
        keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm, serverSecret, HKDFunction.IV, new byte[] {},
                RecordAEADCipher.GCM_IV_LENGTH));
        LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(keySet.getServerWriteIv()));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setClientWriteMacSecret(new byte[0]);
        return keySet;
    }

    private static KeySet getTlsKeySet(TlsContext context) throws NoSuchAlgorithmException, CryptoException {
        ProtocolVersion protocolVersion = context.getChooser().getSelectedProtocolVersion();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        byte[] masterSecret = context.getChooser().getMasterSecret();
        byte[] seed = ArrayConverter.concatenate(context.getChooser().getServerRandom(), context.getChooser()
                .getClientRandom());

        byte[] keyBlock;
        if (protocolVersion.isSSL()) {
            keyBlock = SSLUtils.calculateKeyBlockSSL3(masterSecret, seed,
                    getSecretSetSize(protocolVersion, cipherSuite));
            ;
        } else {
            PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(protocolVersion, cipherSuite);
            keyBlock = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
                    PseudoRandomFunction.KEY_EXPANSION_LABEL, seed, getSecretSetSize(protocolVersion, cipherSuite));
        }
        LOGGER.debug("A new key block was generated: {}", ArrayConverter.bytesToHexString(keyBlock));
        KeyBlockParser parser = new KeyBlockParser(keyBlock, cipherSuite, protocolVersion);
        KeySet keySet = parser.parse();
        return keySet;
    }

    private static int getSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite)
            throws NoSuchAlgorithmException, CryptoException {
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

    private static int getBlockSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite)
            throws CryptoException {
        try {
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            boolean useExplicitIv = protocolVersion.usesExplicitIv();
            int keySize = cipherAlg.getKeySize();
            Cipher cipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(protocolVersion, cipherSuite);
            Mac mac = Mac.getInstance(macAlg.getJavaName());
            int secretSetSize = 2 * keySize + 2 * mac.getMacLength();
            if (!useExplicitIv) {
                secretSetSize += (2 * cipher.getBlockSize());
            }
            return secretSetSize;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not calculate SecretSetSize", ex);
        }
    }

    private static int getAeadSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        int keySize = cipherAlg.getKeySize();
        // GCM in TLS uses 4 bytes long salt (generated in the handshake),
        // 8 bytes long nonce (changed for each new record), and 4 bytes long
        // sequence number used increased in the record
        int saltSize = RecordAEADCipher.GCM_IV_LENGTH - RecordAEADCipher.SEQUENCE_NUMBER_LENGTH;
        int secretSetSize = 2 * keySize + 2 * saltSize;
        return secretSetSize;
    }

    private static int getStreamSecretSetSize(ProtocolVersion protocolVersion, CipherSuite cipherSuite)
            throws NoSuchAlgorithmException {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        int keySize = cipherAlg.getKeySize();
        MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(protocolVersion, cipherSuite);
        Mac mac = Mac.getInstance(macAlg.getJavaName());
        int secretSetSize = (2 * keySize) + mac.getMacLength() + mac.getMacLength();
        return secretSetSize;
    }
}
