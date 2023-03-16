/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public FinishedHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().is13()) {
            if (tlsContext.getTalkingConnectionEndType()
                    != tlsContext.getChooser().getConnectionEndType()) {
                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                    adjustApplicationTrafficSecrets();
                    setServerRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                    if (!tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                        setClientRecordCipher(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
                    }
                } else {
                    acknowledgeFinished(message);
                    setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                }
            } else if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
                    && !tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {

                setClientRecordCipher(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {

                    NewSessionTicketHandler ticketHandler = new NewSessionTicketHandler(tlsContext);
                    if (tlsContext.getPskSets() != null) {
                        for (PskSet pskSet : tlsContext.getPskSets()) {
                            // if psk was derived earliers, skip derivation (especially for state
                            // reusage helpful)
                            if (pskSet.getPreSharedKey() == null) {
                                pskSet.setPreSharedKey(ticketHandler.derivePsk(pskSet));
                            }
                        }
                    }
                }
            }
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setLastClientVerifyData(message.getVerifyData().getValue());
        } else {
            tlsContext.setLastServerVerifyData(message.getVerifyData().getValue());
        }
    }

    private void acknowledgeFinished(FinishedMessage message) {
        tlsContext.setDtlsAcknowledgedRecords(new LinkedList<>());
        int epoch = tlsContext.getReadEpoch();
        long finalSeqNum = tlsContext.getReadSequenceNumber(epoch);
        // acknowledge all records of the given epoch
        for (long seqNum = 0; seqNum <= finalSeqNum; seqNum++) {
            RecordNumber recordNumber =
                    new RecordNumber(BigInteger.valueOf(epoch), BigInteger.valueOf(seqNum));
            tlsContext.getDtlsAcknowledgedRecords().add(recordNumber);
        }
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(
                        tlsContext.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo =
                AlgorithmResolver.getDigestAlgorithm(
                        tlsContext.getChooser().getSelectedProtocolVersion(),
                        tlsContext.getChooser().getSelectedCipherSuite());
        try {
            int macLength =
                    Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            tlsContext.getChooser().getHandshakeSecret(),
                            HKDFunction.DERIVED,
                            ArrayConverter.hexStringToByteArray(""),
                            tlsContext.getChooser().getSelectedProtocolVersion());
            byte[] masterSecret =
                    HKDFunction.extract(hkdfAlgorithm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            masterSecret,
                            HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET,
                            tlsContext.getDigest().getRawBytes(),
                            tlsContext.getChooser().getSelectedProtocolVersion());
            tlsContext.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug(
                    "Set clientApplicationTrafficSecret in Context to {}",
                    clientApplicationTrafficSecret);
            byte[] serverApplicationTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            masterSecret,
                            HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET,
                            tlsContext.getDigest().getRawBytes(),
                            tlsContext.getChooser().getSelectedProtocolVersion());
            tlsContext.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug(
                    "Set serverApplicationTrafficSecret in Context to {}",
                    serverApplicationTrafficSecret);
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set masterSecret in Context to {}", masterSecret);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new AdjustmentException(ex);
        }
    }

    @Override
    public void adjustContextAfterSerialize(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().is13()) {
            if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
                setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            } else {
                adjustApplicationTrafficSecrets();
                setServerRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            }
        }
    }

    private KeySet getKeySet(TlsContext tlsContext, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet =
                    KeySetGenerator.generateKeySet(
                            tlsContext,
                            tlsContext.getChooser().getSelectedProtocolVersion(),
                            keySetType);
            return keySet;
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    private void setServerRecordCipher(Tls13KeySetType keySetType) {
        tlsContext.setActiveServerKeySetType(keySetType);
        LOGGER.debug("Setting cipher for server to use " + keySetType);
        KeySet serverKeySet = getKeySet(tlsContext, tlsContext.getActiveServerKeySetType());

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext
                    .getRecordLayer()
                    .updateDecryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, false));
        } else {
            tlsContext
                    .getRecordLayer()
                    .updateEncryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, true));
        }
    }

    private void setClientRecordCipher(Tls13KeySetType keySetType) {
        tlsContext.setActiveClientKeySetType(keySetType);
        LOGGER.debug("Setting cipher for client to use " + keySetType);
        KeySet clientKeySet = getKeySet(tlsContext, tlsContext.getActiveClientKeySetType());

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            // in DTLS 1.3 epoch 1 is only used for early data, if it was not used, skip it
            if (keySetType == Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS
                    && tlsContext.getChooser().getSelectedProtocolVersion()
                            == ProtocolVersion.DTLS13
                    && tlsContext.getRecordLayer().getDecryptor().isEpochZero()) {
                tlsContext.getRecordLayer().updateDecryptionCipher(null);
            }
            tlsContext
                    .getRecordLayer()
                    .updateDecryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet, false));
        } else {
            // in DTLS 1.3 epoch 1 is only used for early data, if it was not used, skip it
            if (keySetType == Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS
                    && tlsContext.getChooser().getSelectedProtocolVersion()
                            == ProtocolVersion.DTLS13
                    && tlsContext.getRecordLayer().getEncryptor().isEpochZero()) {
                tlsContext.getRecordLayer().updateEncryptionCipher(null);
            }
            tlsContext
                    .getRecordLayer()
                    .updateEncryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet, true));
        }
    }
}
