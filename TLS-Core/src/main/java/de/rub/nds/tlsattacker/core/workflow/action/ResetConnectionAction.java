/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ResetConnectionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean asPlanned;

    public ResetConnectionAction() {
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        LOGGER.info("Terminating Connection");
        try {
            tlsContext.getTransportHandler().closeClientConnection();
        } catch (IOException ex) {
            LOGGER.debug("Could not close client connection", ex);
        }
        LOGGER.info("Resseting Cipher");
        tlsContext.getRecordLayer().setRecordCipher(new RecordNullCipher(tlsContext));
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.getRecordLayer().updateEncryptionCipher();
        LOGGER.info("Resetting SecureRenegotaiton");
        tlsContext.setLastClientVerifyData(new byte[0]);
        tlsContext.setLastServerVerifyData(new byte[0]);
        LOGGER.info("Resetting MessageDigest");
        tlsContext.getDigest().reset();
        LOGGER.info("Resetting ActiveKeySets");
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.NONE);
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.NONE);
        tlsContext.setReadSequenceNumber(0);
        tlsContext.setWriteSequenceNumber(0);
        LOGGER.info("Resetting DTLS numbers and cookie");
        tlsContext.setDtlsCookie(new byte[] {});
        tlsContext.setDtlsNextReceiveSequenceNumber(0);
        tlsContext.setDtlsNextSendSequenceNumber(0);
        tlsContext.setDtlsSendEpoch(0);
        tlsContext.setDtlsNextReceiveEpoch(0);
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
