/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateHandler extends HandshakeMessageHandler<KeyUpdateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyUpdateHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(KeyUpdateMessage message) {
        if (context.getChooser().getTalkingConnectionEnd() != context.getChooser().getConnectionEndType()) {
            adjustApplicationTrafficSecrets();
            setRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        }
    }

    @Override
    public void adjustContextAfterSerialize(KeyUpdateMessage message) {
        adjustApplicationTrafficSecrets();
        setRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getSelectedCipherSuite());

        try {
            Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());

            if (context.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {

                byte[] clientApplicationTrafficSecret =
                    HKDFunction.expandLabel(hkdfAlgortihm, context.getChooser().getClientApplicationTrafficSecret(),
                        HKDFunction.TRAFFICUPD, new byte[0], mac.getMacLength());

                context.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
                LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));

            } else {

                byte[] serverApplicationTrafficSecret =
                    HKDFunction.expandLabel(hkdfAlgortihm, context.getChooser().getServerApplicationTrafficSecret(),
                        HKDFunction.TRAFFICUPD, new byte[0], mac.getMacLength());

                context.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
                LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));

            }

        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new AdjustmentException(ex);
        }
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet =
                KeySetGenerator.generateKeySet(context, context.getChooser().getSelectedProtocolVersion(), keySetType);

            return keySet;
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    private void setRecordCipher(Tls13KeySetType keySetType) {
        try {
            int AEAD_IV_LENGTH = 12;
            KeySet keySet;
            HKDFAlgorithm hkdfAlgortihm =
                AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getSelectedCipherSuite());

            if (context.getChooser().getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {

                context.setActiveClientKeySetType(keySetType);
                LOGGER.debug("Setting cipher for client to use " + keySetType);
                keySet = getKeySet(context, context.getActiveClientKeySetType());

            } else {
                context.setActiveServerKeySetType(keySetType);
                LOGGER.debug("Setting cipher for server to use " + keySetType);
                keySet = getKeySet(context, context.getActiveServerKeySetType());
            }

            if (context.getChooser().getTalkingConnectionEnd() == context.getChooser().getConnectionEndType()) {

                if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {

                    keySet.setClientWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getClientApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setClientWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getClientApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                        AlgorithmResolver.getCipher(context.getChooser().getSelectedCipherSuite()).getKeySize()));
                } else {

                    keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getServerApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setServerWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getServerApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                        AlgorithmResolver.getCipher(context.getChooser().getSelectedCipherSuite()).getKeySize()));
                }

                RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(context, keySet);
                context.getRecordLayer().updateEncryptionCipher(recordCipherClient);

            } else if (context.getChooser().getTalkingConnectionEnd() != context.getChooser().getConnectionEndType()) {

                if (context.getChooser().getTalkingConnectionEnd() == ConnectionEndType.SERVER) {

                    keySet.setServerWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getServerApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setServerWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getServerApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                        AlgorithmResolver.getCipher(context.getChooser().getSelectedCipherSuite()).getKeySize()));

                } else {

                    keySet.setClientWriteIv(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getClientApplicationTrafficSecret(), HKDFunction.IV, new byte[0], AEAD_IV_LENGTH));

                    keySet.setClientWriteKey(HKDFunction.expandLabel(hkdfAlgortihm,
                        context.getClientApplicationTrafficSecret(), HKDFunction.KEY, new byte[0],
                        AlgorithmResolver.getCipher(context.getChooser().getSelectedCipherSuite()).getKeySize()));
                }

                RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(context, keySet);
                context.getRecordLayer().updateDecryptionCipher(recordCipherClient);

            }

        } catch (CryptoException ex) {
            throw new AdjustmentException(ex);
        }

    }
}
