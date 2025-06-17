/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CoreClientHelloPreparator<T extends CoreClientHelloMessage>
        extends HelloMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    public CoreClientHelloPreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ClientHelloMessage");
        prepareProtocolVersion(msg);
        prepareRandom();
        prepareCompressions(msg);
        prepareCompressionLength(msg);
        prepareCipherSuites(msg);
        prepareCipherSuitesLength(msg);
        if (isDTLS()) {
            prepareCookie(msg);
            prepareCookieLength(msg);
        }
        prepareExtensions();
        prepareExtensionLength();
        prepareSessionID();
        prepareSessionIDLength();
    }

    protected void prepareRandom() {
        if (mustRetainPreviousClientRandom()) {
            msg.setRandom(chooser.getClientRandom());
        } else {
            super.prepareRandom();
        }
    }

    // for DTLS, the random value of a second ClientHello message should be
    // the same as that of the first (at least in case the first prompted
    // HelloVerifyResponse from server). The same applies for HelloRetryRequest flows in TLS 1.3
    private boolean mustRetainPreviousClientRandom() {
        return (isDTLS() || isHelloRetryRequestFlow()) && hasClientRandom();
    }

    private void prepareSessionID() {
        boolean isResumptionWithSessionTicket = false;
        if (msg.containsExtension(ExtensionType.SESSION_TICKET)) {
            SessionTicketTLSExtensionMessage extensionMessage =
                    msg.getExtension(SessionTicketTLSExtensionMessage.class);
            if (extensionMessage != null
                    && extensionMessage.getSessionTicket().getIdentityLength().getValue() > 0) {
                isResumptionWithSessionTicket = true;
            }
        }
        if (isResumptionWithSessionTicket && chooser.getConfig().isOverrideSessionIdForTickets()) {
            msg.setSessionId(chooser.getConfig().getDefaultClientTicketResumptionSessionId());
        } else if (chooser.getContext().getTlsContext().getServerSessionId() == null) {
            msg.setSessionId(chooser.getClientSessionId());
        } else {
            msg.setSessionId(chooser.getServerSessionId());
        }
        LOGGER.debug("SessionId: {}", msg.getSessionId().getValue());
    }

    private boolean isDTLS() {
        return chooser.getSelectedProtocolVersion().isDTLS();
    }

    /**
     * Determines if we are in a HelloRetryRequest flow. Since other information from the context
     * may be retained from a previous handshake, we check the start of the digest for the 'message
     * hash' handshake message type which is unique to HRR flows and won't be retained after a
     * connection reset.
     *
     * @return true if the digest indicates that we are in a HelloRetryRequest TLS 1.3 flow
     */
    private boolean isHelloRetryRequestFlow() {
        if (chooser.getContext().getTlsContext().getSelectedProtocolVersion()
                == ProtocolVersion.TLS13) {
            return chooser.getContext().getTlsContext().getDigest().getRawBytes().length > 0
                    && chooser.getContext().getTlsContext().getDigest().getRawBytes()[0]
                            == HandshakeMessageType.MESSAGE_HASH.getValue();
        }
        return false;
    }

    private byte[] convertCompressions(List<CompressionMethod> compressionList) {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        for (CompressionMethod compression : compressionList) {
            stream.write(compression.getArrayValue());
        }
        return stream.toByteArray();
    }

    private byte[] convertCipherSuites(List<CipherSuite> suiteList) {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        for (CipherSuite suite : suiteList) {
            stream.write(suite.getByteValue());
        }
        return stream.toByteArray();
    }

    private void prepareProtocolVersion(T msg) {
        if (chooser.getConfig().getHighestProtocolVersion().isTLS13()) {
            msg.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        } else if (chooser.getConfig().getHighestProtocolVersion().isDTLS13()) {
            msg.setProtocolVersion(ProtocolVersion.DTLS12.getValue());
        } else {
            msg.setProtocolVersion(chooser.getConfig().getHighestProtocolVersion().getValue());
        }
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }

    private void prepareCompressions(T msg) {
        if (chooser.getConfig().getHighestProtocolVersion().is13()) {
            msg.setCompressions(CompressionMethod.NULL.getArrayValue());
        } else {
            msg.setCompressions(
                    convertCompressions(
                            chooser.getConfig().getDefaultClientSupportedCompressionMethods()));
        }
        LOGGER.debug("Compressions: {}", msg.getCompressions().getValue());
    }

    private void prepareCompressionLength(T msg) {
        msg.setCompressionLength(msg.getCompressions().getValue().length);
        LOGGER.debug("CompressionLength: {}", msg.getCompressionLength().getValue());
    }

    private void prepareCipherSuites(T msg) {
        msg.setCipherSuites(
                convertCipherSuites(chooser.getConfig().getDefaultClientSupportedCipherSuites()));
        LOGGER.debug("CipherSuites: {}", msg.getCipherSuites().getValue());
    }

    private void prepareCipherSuitesLength(T msg) {
        msg.setCipherSuiteLength(msg.getCipherSuites().getValue().length);
        LOGGER.debug("CipherSuitesLength: {}", msg.getCipherSuiteLength().getValue());
    }

    private boolean hasClientRandom() {
        return chooser.getContext().getTlsContext().getClientRandom() != null;
    }

    private void prepareCookie(T msg) {
        if (chooser.getSelectedProtocolVersion().isDTLS13()) {
            msg.setCookie(new byte[0]);
        } else {
            msg.setCookie(chooser.getDtlsCookie());
        }
        LOGGER.debug("Cookie: {}", msg.getCookie().getValue());
    }

    private void prepareCookieLength(T msg) {
        msg.setCookieLength((byte) msg.getCookie().getValue().length);
        LOGGER.debug("CookieLength: {}", msg.getCookieLength().getValue());
    }

    @Override
    public void afterPrepare() {
        afterPrepareExtensions();
    }
}
