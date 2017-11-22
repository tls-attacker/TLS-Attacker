/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    public FinishedHandler(TlsContext context) {
        super(context);
    }

    @Override
    public FinishedMessageParser getParser(byte[] message, int pointer) {
        return new FinishedMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public FinishedMessagePreparator getPreparator(FinishedMessage message) {
        return new FinishedMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public FinishedMessageSerializer getSerializer(FinishedMessage message) {
        return new FinishedMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(FinishedMessage message) {
        if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT
                && tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            adjustRecordCipherForClientFin();
        }
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                adjustApplicationTrafficSecrets();
                tlsContext.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            }
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setLastClientVerifyData(message.getVerifyData().getValue());
            if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.SERVER
                    && tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                adjustRecordCipherForApplicationData();
            }
        } else {
            tlsContext.setLastServerVerifyData(message.getVerifyData().getValue());
        }
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                .getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(tlsContext.getChooser()
                .getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());
        try {
            int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    tlsContext.getHandshakeSecret(), HKDFunction.DERIVED, ArrayConverter.hexStringToByteArray(""));
            byte[] masterSecret = HKDFunction.extract(hkdfAlgortihm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
            byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set masterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    private void adjustRecordCipherForClientFin() {
        LOGGER.debug("Adjusting recordCipher after encrypting EOED using different key");
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        updateRecordCipher(tlsContext.getSelectedCipherSuite(), tlsContext.getSelectedCipherSuite());
        // Set the correct SequenceNumbers
        tlsContext.setWriteSequenceNumber(0);
        tlsContext.setReadSequenceNumber(2);
    }

    @Override
    public void adjustTlsContextAfterSerialize(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
                adjustRecordCipherForApplicationData();
            } else if (tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                adjustRecordCipherForEndOfEarlyData();
            }

        }
    }

    private void adjustRecordCipherForApplicationData() {
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        updateRecordCipher(tlsContext.getSelectedCipherSuite(), tlsContext.getSelectedCipherSuite());
        tlsContext.setWriteSequenceNumber(0);
        tlsContext.setReadSequenceNumber(0);
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet = KeySetGenerator.generateKeySet(context, context.getSelectedProtocolVersion(), keySetType);
            return keySet;
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    private void adjustRecordCipherForEndOfEarlyData() {
        LOGGER.debug("Adjusting recordCipher to decrypt EndOfEarlyData");
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
        updateRecordCipher(tlsContext.getSelectedCipherSuite(), tlsContext.getEarlyDataCipherSuite());
        // Restore the correct SequenceNumber
        tlsContext.setReadSequenceNumber(1);
    }

    private void updateRecordCipher(CipherSuite cipherWrite, CipherSuite cipherRead) {
        KeySet keySetWrite = getKeySet(tlsContext, tlsContext.getActiveKeySetTypeWrite());
        KeySet keySetRead = getKeySet(tlsContext, tlsContext.getActiveKeySetTypeRead());
        LOGGER.debug("Setting new Cipher and Key in RecordLayer");
        RecordCipher recordCipherWrite = RecordCipherFactory.getRecordCipher(tlsContext, keySetWrite, cipherWrite);
        RecordCipher recordCipherRead = RecordCipherFactory.getRecordCipher(tlsContext, keySetRead, cipherRead);
        if (tlsContext.getRecordLayer().getEncryptor().getKeySet().getKeySetType() != tlsContext
                .getActiveKeySetTypeWrite()) {
            tlsContext.getRecordLayer().setRecordCipher(recordCipherWrite);
            tlsContext.getRecordLayer().updateEncryptionCipher();
        }
        if (tlsContext.getRecordLayer().getDecryptor().getKeySet().getKeySetType() != tlsContext
                .getActiveKeySetTypeRead()) {
            tlsContext.getRecordLayer().setRecordCipher(recordCipherRead);
            tlsContext.getRecordLayer().updateDecryptionCipher();
        }
    }
}
