/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.dtls.FragmentManager;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.Objects;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ResetConnectionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean asPlanned;

    private Boolean resetContext = true;

    public ResetConnectionAction() {
    }

    public ResetConnectionAction(boolean resetContext) {
        this.resetContext = resetContext;
    }

    public ResetConnectionAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.info("Terminating Connection");
        try {
            tlsContext.getTransportHandler().closeClientConnection();
        } catch (IOException ex) {
            LOGGER.debug("Could not close client connection", ex);
        }

        if (resetContext) {
            LOGGER.info("Resetting Cipher");
            tlsContext.getRecordLayer().resetDecryptor();
            tlsContext.getRecordLayer().resetEncryptor();
            tlsContext.getRecordLayer().updateDecryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
            tlsContext.getRecordLayer().updateEncryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
            tlsContext.getRecordLayer().setWriteEpoch(0);
            tlsContext.getRecordLayer().setReadEpoch(0);
            LOGGER.info("Resetting SecureRenegotiation");
            tlsContext.setLastClientVerifyData(null);
            tlsContext.setLastServerVerifyData(null);
            LOGGER.info("Resetting MessageDigest");
            tlsContext.getDigest().reset();
            LOGGER.info("Resetting ActiveKeySets");
            tlsContext.setActiveClientKeySetType(Tls13KeySetType.NONE);
            tlsContext.setActiveServerKeySetType(Tls13KeySetType.NONE);
            LOGGER.info("Resetting TLS 1.3 HRR and PSK values");
            tlsContext.setExtensionCookie(null);
            tlsContext.setLastClientHello(null);
            tlsContext.setPsk(null);
            tlsContext.setEarlyDataPSKIdentity(null);
            tlsContext.setEarlyDataPsk(null);
            tlsContext.setEarlySecret(null);
            tlsContext.setEarlyDataCipherSuite(null);
            LOGGER.info("Resetting DTLS numbers and cookie");
            tlsContext.setDtlsCookie(null);
            tlsContext.setDtlsReadHandshakeMessageSequence(0);
            tlsContext.setDtlsWriteHandshakeMessageSequence(0);
            tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
            tlsContext.setDtlsFragmentManager(new FragmentManager(state.getConfig()));
            tlsContext.getDtlsReceivedHandshakeMessageSequences().clear();
        }

        LOGGER.info("Reopening Connection");
        try {
            tlsContext.getTransportHandler().initialize();
            asPlanned = true;
        } catch (IOException ex) {
            LOGGER.debug("Could not initialize TransportHandler", ex);
            asPlanned = false;
        }

        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
        asPlanned = null;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted() && Objects.equals(asPlanned, Boolean.TRUE);
    }

}
