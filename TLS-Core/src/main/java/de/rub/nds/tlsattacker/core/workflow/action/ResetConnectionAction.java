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
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.IOException;
import java.util.Objects;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ResetConnectionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean asPlanned;

    public ResetConnectionAction() {
    }

    public ResetConnectionAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();
        TcpContext tcpContext = state.getContext(getConnectionAlias()).getTcpContext();

        LOGGER.info("Terminating Connection");
        try {
            tcpContext.getTransportHandler().closeClientConnection();
        } catch (IOException ex) {
            LOGGER.debug("Could not close client connection", ex);
        }
        LOGGER.info("Resetting Cipher");
        if (tlsContext.getRecordLayer() != null) {
            tlsContext.getRecordLayer().resetDecryptor();
            tlsContext.getRecordLayer().resetEncryptor();
            tlsContext.getRecordLayer().updateDecryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
            tlsContext.getRecordLayer().updateEncryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
            tlsContext.getRecordLayer().setWriteEpoch(0);
            tlsContext.getRecordLayer().setReadEpoch(0);
        }
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
        if (tlsContext.getDtlsFragmentLayer() != null) {
            tlsContext.getDtlsFragmentLayer().setReadHandshakeMessageSequence(0);
            tlsContext.getDtlsFragmentLayer().setWriteHandshakeMessageSequence(0);
            tlsContext.getDtlsFragmentLayer().resetFragmentManager(state.getConfig());
        }
        tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
        tlsContext.getDtlsReceivedHandshakeMessageSequences().clear();
        LOGGER.info("Reopening Connection");
        try {
            tcpContext.getTransportHandler().initialize();
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
