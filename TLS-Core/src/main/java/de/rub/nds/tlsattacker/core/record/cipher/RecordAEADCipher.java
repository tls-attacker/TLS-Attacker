/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordAEADCipher extends RecordCipher {
    
    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * sequence Number length in bytes
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;

    /**
     * AEAD tag length in bytes for regular ciphers
     */
    public static final int AEAD_TAG_LENGTH = 16;

    /**
     * AEAD tag length in bytes for CCM_8 ciphers
     */
    public static final int AEAD_CCM_8_TAG_LENGTH = 8;

    /**
     * AEAD iv length in bytes
     */
    public static final int AEAD_IV_LENGTH = 12;

    /**
     * Stores the computed tag length
     */
    private final int aeadTagLength;
    
    public RecordAEADCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
        encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
        decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());
        
        if (cipherSuite.isCCM_8()) {
            aeadTagLength = AEAD_CCM_8_TAG_LENGTH;
        } else {
            aeadTagLength = AEAD_TAG_LENGTH;
        }
    }

    /**
     * Used to prepare AAD for TLS1.3 only!
     */
    private byte[] prepareAeadParameters(byte[] nonce, byte[] iv) {
        byte[] param = new byte[AEAD_IV_LENGTH];
        for (int i = 0; i < AEAD_IV_LENGTH; i++) {
            param[i] = (byte) (iv[i] ^ nonce[i]);
        }
        return param;
    }
    
    @Override
    public boolean isUsingPadding() {
        return version.isTLS13() || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS
                || context.getActiveKeySetTypeRead() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS;
    }
    
    @Override
    public boolean isUsingMac() {
        return false;
    }
    
    @Override
    public boolean isUsingTags() {
        return true;
    }
    
    public int getTagSize() {
        if (cipherSuite.usesStrictExplicitIv() || version.isTLS13()) {
            return aeadTagLength;
        } else {
            return SEQUENCE_NUMBER_LENGTH + aeadTagLength;
        }
    }
    
    public void encryptTls12(Record record) throws CryptoException {
        
        byte[] explicitNonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        record.getComputations().setExplicitNonce(explicitNonce);
        explicitNonce = record.getComputations().getExplicitNonce().getValue();
        
        byte[] implicitNonce = getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType());
        record.getComputations().setImplicitNonce(implicitNonce);
        implicitNonce = record.getComputations().getImplicitNonce().getValue();
        
        byte[] totalNonce;
        if (cipherSuite.usesStrictExplicitIv()) {
            totalNonce = explicitNonce;
        } else {
            totalNonce = ArrayConverter.concatenate(implicitNonce, explicitNonce);
        }
        record.getComputations().setNonce(totalNonce);
        totalNonce = record.getComputations().getNonce().getValue();
        
        LOGGER.debug("Encrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(totalNonce));
        
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        additionalAuthenticatedData = record.getComputations().getAuthenticatedMetaData().getValue();
        
        LOGGER.debug("Encrypting AEAD with the following AAD: {}",
                ArrayConverter.bytesToHexString(additionalAuthenticatedData));
        
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        byte[] wholeCipherText = encryptCipher.encrypt(totalNonce, getTagSize() * 8, additionalAuthenticatedData,
                cleanBytes);
        
        byte[] onlyCiphertext = Arrays.copyOfRange(wholeCipherText, 0, wholeCipherText.length - AEAD_TAG_LENGTH);
        
        byte[] authenticationTag = Arrays.copyOfRange(wholeCipherText, wholeCipherText.length - aeadTagLength,
                wholeCipherText.length);
        record.getComputations().setAuthenticationTag(authenticationTag);
        authenticationTag = record.getComputations().getAuthenticationTag().getValue();
        
        record.getComputations().setCiphertext(ArrayConverter.concatenate(onlyCiphertext, authenticationTag));
        record.setProtocolMessageBytes(ArrayConverter.concatenate(explicitNonce, wholeCipherText, authenticationTag));
    }
    
    public void encryptTls13(Record record) throws CryptoException {
        byte[] sequenceNumberBytes = ArrayConverter.longToBytes(context.getWriteSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        LOGGER.debug("SQN bytes: " + ArrayConverter.bytesToHexString(sequenceNumberBytes));
        byte[] nonce = ArrayConverter.concatenate(new byte[AEAD_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                sequenceNumberBytes);
        LOGGER.debug("NonceBytes:" + ArrayConverter.bytesToHexString(nonce));
        
        byte[] encryptIv = prepareAeadParameters(nonce, getEncryptionIV());
        record.getComputations().setNonce(encryptIv);
        encryptIv = record.getComputations().getNonce().getValue();
        LOGGER.debug("Encrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(encryptIv));
        
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        additionalAuthenticatedData = record.getComputations().getAuthenticatedMetaData().getValue();
        
        LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIv));
        byte[] cipherText;
        if (version == ProtocolVersion.TLS13 || version == ProtocolVersion.TLS13_DRAFT25
                || version == ProtocolVersion.TLS13_DRAFT26 || version == ProtocolVersion.TLS13_DRAFT27
                || version == ProtocolVersion.TLS13_DRAFT28) {
            LOGGER.debug("AAD:" + additionalAuthenticatedData);
            cipherText = encryptCipher.encrypt(encryptIv, getTagSize() * 8, additionalAuthenticatedData,
                    record.getCleanProtocolMessageBytes().getValue());
        } else {
            cipherText = encryptCipher.encrypt(encryptIv, getTagSize() * 8, record.getCleanProtocolMessageBytes().getValue());
        }
        byte[] onlyCipherText = Arrays.copyOfRange(cipherText, 0, record.getCleanProtocolMessageBytes().getValue().length - getTagSize());
        byte[] tag = Arrays.copyOfRange(cipherText, cipherText.length - getTagSize(), cipherText.length);
        record.getComputations().setAuthenticationTag(tag);
        record.getComputations().setCiphertext(onlyCipherText);
        record.setProtocolMessageBytes(ArrayConverter.concatenate(record.getComputations().getCiphertext().getValue(), record.getComputations().getAuthenticationTag().getValue()));
    }
    
    public void decryptTls12(Record record) throws CryptoException {
        byte[] protocolBytes = record.getProtocolMessageBytes().getValue();
        DecryptionParser parser = new DecryptionParser(0, protocolBytes);
        
        byte[] explicitNonce = parser.parseByteArrayField(SEQUENCE_NUMBER_LENGTH);
        record.getComputations().setExplicitNonce(explicitNonce);
        explicitNonce = record.getComputations().getExplicitNonce().getValue();
        
        byte[] implicitNonce = getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType());
        record.getComputations().setImplicitNonce(implicitNonce);
        implicitNonce = record.getComputations().getImplicitNonce().getValue();
        
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        additionalAuthenticatedData = record.getComputations().getAuthenticatedMetaData().getValue();
        
        LOGGER.debug("Decrypting AEAD with the following AAD: {}",
                ArrayConverter.bytesToHexString(additionalAuthenticatedData));
        
        byte[] totalNonce;
        if (cipherSuite.usesStrictExplicitIv()) {
            totalNonce = explicitNonce;
        } else {
            totalNonce = ArrayConverter.concatenate(implicitNonce, explicitNonce);
        }
        record.getComputations().setNonce(totalNonce);
        totalNonce = record.getComputations().getNonce().getValue();
        LOGGER.debug("Decrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(totalNonce));
        
        byte[] cipherTextOnly = parser.parseByteArrayField(parser.getBytesLeft() - getTagSize());
        
        byte[] authenticationTag = parser.parseByteArrayField(parser.getBytesLeft());
        record.getComputations().setAuthenticationTag(authenticationTag);
        authenticationTag = record.getComputations().getAuthenticationTag().getValue();
        
        byte[] plaintext = decryptCipher.decrypt(totalNonce, getTagSize() * 8, additionalAuthenticatedData,
                ArrayConverter.concatenate(cipherTextOnly, authenticationTag));
        record.setCleanProtocolMessageBytes(plaintext);
    }
    
    public void decryptTls13(Record record) throws CryptoException {
        
        LOGGER.debug("Decrypting using SQN:" + context.getReadSequenceNumber());
        byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getReadSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        byte[] nonce = ArrayConverter
                .concatenate(new byte[AEAD_IV_LENGTH - SEQUENCE_NUMBER_LENGTH], sequenceNumberByte);
        
        byte[] decryptIV = prepareAeadParameters(nonce, getDecryptionIV());
        record.getComputations().setNonce(decryptIV);
        decryptIV = record.getComputations().getNonce().getValue();
        LOGGER.debug("Decrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV));
        
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        additionalAuthenticatedData = record.getComputations().getAuthenticatedMetaData().getValue();
        
        byte[] cipherText = Arrays.copyOfRange(record.getProtocolMessageBytes().getValue(), 0, record
                .getProtocolMessageBytes().getValue().length - getTagSize());
        byte[] authenticationTag = Arrays.copyOfRange(record.getProtocolMessageBytes().getValue(), record
                .getProtocolMessageBytes().getValue().length - getTagSize(), record.getProtocolMessageBytes()
                        .getValue().length);
        record.getComputations().setCiphertext(ArrayConverter.concatenate(cipherText, authenticationTag));
        byte[] wholeCipherText = record.getComputations().getCiphertext().getValue();
        
        byte[] plaintext;
        if (version == ProtocolVersion.TLS13 || version == ProtocolVersion.TLS13_DRAFT25
                || version == ProtocolVersion.TLS13_DRAFT26 || version == ProtocolVersion.TLS13_DRAFT27
                || version == ProtocolVersion.TLS13_DRAFT28) {
            plaintext = decryptCipher.decrypt(decryptIV, aeadTagLength * 8, additionalAuthenticatedData,
                    wholeCipherText);
        } else {
            plaintext = decryptCipher.decrypt(decryptIV, aeadTagLength * 8, wholeCipherText);
        }
        
        record.setCleanProtocolMessageBytes(plaintext);
    }
    
    @Override
    public void encrypt(Record record) throws CryptoException {
        LOGGER.debug("Encrypting Record");
        
        record.getComputations().setCipherKey(getKeySet().getWriteKey(context.getChooser().getConnectionEndType()));
        
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            encryptTls13(record);
        } else {
            encryptTls12(record);
        }
    }
    
    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record");
        
        record.getComputations().setCipherKey(getKeySet().getReadKey(context.getChooser().getConnectionEndType()));
        
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            decryptTls13(record);
        } else {
            decryptTls12(record);
        }
    }
    
    public byte[] getDecryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getReadSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }
    
    public byte[] getEncryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }
    
    class DecryptionParser extends Parser<Object> {
        
        public DecryptionParser(int startposition, byte[] array) {
            super(startposition, array);
        }
        
        @Override
        public Object parse() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }
        
        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }
        
        @Override
        public int getPointer() {
            return super.getPointer();
        }
        
    }
}
