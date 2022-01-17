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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;

public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public FinishedHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(FinishedMessage message) {
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (context.getTalkingConnectionEndType() != context.getChooser().getConnectionEndType()) {
                if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                    adjustApplicationTrafficSecrets();
                    setServerRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                } else {
                    setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                }
            } else if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                || !context.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                setClientRecordCipher(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

                if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {

                    NewSessionTicketHandler ticketHandler = new NewSessionTicketHandler(context);
                    if (context.getPskSets() != null) {
                        for (PskSet pskSet : context.getPskSets()) {
                            // if psk was derived earliers, skip derivation (especially for state reusage helpful)
                            if (pskSet.getPreSharedKey() == null) {
                                pskSet.setPreSharedKey(ticketHandler.derivePsk(pskSet));
                            }
                        }
                    }
                }
            }
        }
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            context.setLastClientVerifyData(message.getVerifyData().getValue());
        } else {
            context.setLastServerVerifyData(message.getVerifyData().getValue());
        }
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
            context.getChooser().getSelectedProtocolVersion(), context.getChooser().getSelectedCipherSuite());
        try {
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                context.getChooser().getHandshakeSecret(), HKDFunction.DERIVED,
                ArrayConverter.hexStringToByteArray(""));
            byte[] masterSecret = HKDFunction.extract(hkdfAlgorithm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                masterSecret, HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
            byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                masterSecret, HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
            context.setMasterSecret(masterSecret);
            LOGGER.debug("Set masterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new AdjustmentException(ex);
        }
    }

    @Override
    public void adjustContextAfterSerialize(FinishedMessage message) {
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
                setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            } else {
                adjustApplicationTrafficSecrets();
                setServerRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            }

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

    private void setServerRecordCipher(Tls13KeySetType keySetType) {
        context.setActiveServerKeySetType(keySetType);
        LOGGER.debug("Setting cipher for server to use " + keySetType);
        KeySet serverKeySet = getKeySet(context, context.getActiveServerKeySetType());

        if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            context.getRecordLayer().updateDecryptionCipher(RecordCipherFactory.getRecordCipher(context, serverKeySet));
        } else {
            context.getRecordLayer().updateEncryptionCipher(RecordCipherFactory.getRecordCipher(context, serverKeySet));
        }
    }

    private void setClientRecordCipher(Tls13KeySetType keySetType) {
        context.setActiveClientKeySetType(keySetType);
        LOGGER.debug("Setting cipher for client to use " + keySetType);
        KeySet clientKeySet = getKeySet(context, context.getActiveClientKeySetType());

        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            context.getRecordLayer().updateDecryptionCipher(RecordCipherFactory.getRecordCipher(context, clientKeySet));
        } else {
            context.getRecordLayer().updateEncryptionCipher(RecordCipherFactory.getRecordCipher(context, clientKeySet));
        }
    }
}
