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
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
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
    public FinishedParser getParser(byte[] message, int pointer) {
        return new FinishedParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public FinishedPreparator getPreparator(FinishedMessage message) {
        return new FinishedPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public FinishedSerializer getSerializer(FinishedMessage message) {
        return new FinishedSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()) {
                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                    adjustApplicationTrafficSecrets();
                    setServerRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                } else {
                    setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
                }
            } else if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                || !tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
                setClientRecordCipher(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                    NewSessionTicketHandler ticketHandler = (NewSessionTicketHandler) HandlerFactory
                        .getHandshakeHandler(tlsContext, HandshakeMessageType.NEW_SESSION_TICKET);
                    if (tlsContext.getPskSets() != null) {
                        for (PskSet pskSet : tlsContext.getPskSets()) {
                            // if psk was derived earliers, skip derivation (especially for state reusage helpful)
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

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgorithm =
            AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
            tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());
        try {
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                tlsContext.getChooser().getHandshakeSecret(), HKDFunction.DERIVED,
                ArrayConverter.hexStringToByteArray(""));
            byte[] masterSecret = HKDFunction.extract(hkdfAlgorithm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                masterSecret, HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
            byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                masterSecret, HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set masterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new AdjustmentException(ex);
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
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
        tlsContext.setActiveServerKeySetType(keySetType);
        LOGGER.debug("Setting cipher for server to use " + keySetType);
        KeySet serverKeySet = getKeySet(tlsContext, tlsContext.getActiveServerKeySetType());

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.getRecordLayer()
                .updateDecryptionCipher(RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet));
        } else {
            tlsContext.getRecordLayer()
                .updateEncryptionCipher(RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet));
        }
    }

    private void setClientRecordCipher(Tls13KeySetType keySetType) {
        tlsContext.setActiveClientKeySetType(keySetType);
        LOGGER.debug("Setting cipher for client to use " + keySetType);
        KeySet clientKeySet = getKeySet(tlsContext, tlsContext.getActiveClientKeySetType());

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            tlsContext.getRecordLayer()
                .updateDecryptionCipher(RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet));
        } else {
            tlsContext.getRecordLayer()
                .updateEncryptionCipher(RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet));
        }
    }
}
