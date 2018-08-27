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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.Session;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <Message>
 *            The ClientKeyExchangeMessage that should be Handled
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    public void adjustPremasterSecret(ClientKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
            tlsContext.setPreMasterSecret(premasterSecret);
            LOGGER.debug("Set PremasterSecret in Context to " + ArrayConverter.bytesToHexString(premasterSecret));
        } else {
            LOGGER.debug("Did not set in Context PremasterSecret");
        }
    }

    protected byte[] calculateMasterSecret(ClientKeyExchangeMessage message) throws CryptoException {
        Chooser chooser = tlsContext.getChooser();
        if (chooser.getSelectedProtocolVersion() == ProtocolVersion.SSL3) {
            LOGGER.debug("Calculate SSL MasterSecret with Client and Server Nonces, which are: "
                    + ArrayConverter.bytesToHexString(message.getComputations().getClientServerRandom().getValue()));
            return SSLUtils.calculateMasterSecretSSL3(chooser.getPreMasterSecret(), message.getComputations()
                    .getClientServerRandom().getValue());
        } else {
            PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                    chooser.getSelectedCipherSuite());
            if (chooser.isUseExtendedMasterSecret()) {
                LOGGER.debug("Calculating ExtendedMasterSecret");
                byte[] sessionHash = tlsContext.getDigest().digest(chooser.getSelectedProtocolVersion(),
                        chooser.getSelectedCipherSuite());
                LOGGER.debug("Premastersecret: " + ArrayConverter.bytesToHexString(chooser.getPreMasterSecret()));

                LOGGER.debug("SessionHash: " + ArrayConverter.bytesToHexString(sessionHash));
                byte[] extendedMasterSecret = PseudoRandomFunction.compute(prfAlgorithm, chooser.getPreMasterSecret(),
                        PseudoRandomFunction.EXTENDED_MASTER_SECRET_LABEL, sessionHash,
                        HandshakeByteLength.MASTER_SECRET);
                return extendedMasterSecret;
            } else {
                LOGGER.debug("Calculating MasterSecret");
                byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, chooser.getPreMasterSecret(),
                        PseudoRandomFunction.MASTER_SECRET_LABEL, message.getComputations().getClientServerRandom()
                                .getValue(), HandshakeByteLength.MASTER_SECRET);
                return masterSecret;
            }
        }
    }

    public void adjustMasterSecret(ClientKeyExchangeMessage message) {
        byte[] masterSecret;
        try {
            masterSecret = calculateMasterSecret(message);
        } catch (CryptoException ex) {
            throw new UnsupportedOperationException("Could not calculate masterSecret", ex);
        }
        tlsContext.setMasterSecret(masterSecret);
        LOGGER.debug("Set MasterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
    }

    protected void setRecordCipher() {
        KeySet keySet = getKeySet(tlsContext);
        LOGGER.debug("Setting new Cipher in RecordLayer");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
    }

    protected void spawnNewSession() {
        Session session = new Session(tlsContext.getChooser().getServerSessionId(), tlsContext.getChooser()
                .getMasterSecret());
        tlsContext.addNewSession(session);
        LOGGER.debug("Spawning new resumable Session");
    }

    private KeySet getKeySet(TlsContext context) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(context);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }
}
