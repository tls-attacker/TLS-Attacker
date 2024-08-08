/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.QuicFrameLayer;
import de.rub.nds.tlsattacker.core.layer.impl.QuicPacketLayer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ResetConnection")
public class ResetConnectionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean asPlanned;

    private Boolean resetContext = true;

    private Boolean switchToIpv6 = false;

    public ResetConnectionAction() {}

    public ResetConnectionAction(boolean resetContext) {
        this.resetContext = resetContext;
    }

    public ResetConnectionAction(boolean resetContext, boolean switchToIpv6) {
        this.resetContext = resetContext;
        this.switchToIpv6 = switchToIpv6;
    }

    public ResetConnectionAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        Context context = state.getContext(getConnectionAlias());
        TlsContext tlsContext = context.getTlsContext();
        TcpContext tcpContext = context.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.info("Terminating Connection");
        try {
            tcpContext.getTransportHandler().closeClientConnection();
        } catch (IOException ex) {
            LOGGER.debug("Could not close client connection", ex);
        }
        if (resetContext) {
            LOGGER.info("Resetting Cipher");
            if (tlsContext.getRecordLayer() != null) {
                tlsContext.getRecordLayer().resetDecryptor();
                tlsContext.getRecordLayer().resetEncryptor();
                tlsContext
                        .getRecordLayer()
                        .updateDecryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
                tlsContext
                        .getRecordLayer()
                        .updateEncryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
                tlsContext.getRecordLayer().setWriteEpoch(0);
                tlsContext.getRecordLayer().setReadEpoch(0);
            }
            LOGGER.info("Resetting KeyShareStores");
            tlsContext.setServerKeyShareStoreEntry(null);
            tlsContext.setClientKeyShareStoreEntryList(null);
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
            tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
            tlsContext.getDtlsReceivedHandshakeMessageSequences().clear();
            tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
            tlsContext.getDtlsReceivedHandshakeMessageSequences().clear();
            tlsContext.setDtlsCookie(null);
            if (tlsContext.getDtlsFragmentLayer() != null) {
                tlsContext.getDtlsFragmentLayer().resetFragmentManager(state.getConfig());
                tlsContext.getDtlsFragmentLayer().setReadHandshakeMessageSequence(0);
                tlsContext.getDtlsFragmentLayer().setWriteHandshakeMessageSequence(0);
            }
            LOGGER.info("Resetting QUIC settings");
            if (context.getConfig().getQuic()) {
                QuicContext quicContext = context.getQuicContext();
                quicContext.reset();
                ((QuicPacketLayer) context.getLayerStack().getLayer(QuicPacketLayer.class))
                        .clearReceivedPacketBuffer();
                ((QuicFrameLayer) context.getLayerStack().getLayer(QuicFrameLayer.class))
                        .clearCryptoFrameBuffer();
            }
        }

        LOGGER.info("Reopening Connection");
        try {
            if (switchToIpv6) {
                tcpContext.getTransportHandler().setUseIpv6(true);
            }
            tcpContext.getTransportHandler().initialize();
            asPlanned = true;
        } catch (IOException ex) {
            LOGGER.debug("Could not initialize TransportHandler", ex);
            asPlanned = false;
        }

        setExecuted(true);
    }

    @Override
    public String toString() {
        return "RestConnectionAction: "
                + (isExecuted() ? "\n" : "(not executed)\n")
                + "\tReset context: "
                + resetContext
                + "\n\tSwitch to ipv6: "
                + switchToIpv6;
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
