/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloPreparator extends HelloMessagePreparator<ClientHelloMessage> {

    private final ClientHelloMessage msg;

    public ClientHelloPreparator(Chooser chooser, ClientHelloMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ClientHelloMessage");
        prepareProtocolVersion(msg);
        prepareUnixTime();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();
        prepareCompressions(msg);
        prepareCompressionLength(msg);
        prepareCipherSuites(msg);
        prepareCipherSuitesLength(msg);
        if (hasHandshakeCookie()) {
            prepareCookie(msg);
            prepareCookieLength(msg);
        }
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareSessionID() {
        msg.setSessionId(chooser.getClientSessionId());
    }

    private byte[] convertCompressions(List<CompressionMethod> compressionList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CompressionMethod compression : compressionList) {
            try {
                stream.write(compression.getArrayValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare ClientHelloMessage. Failed to write Ciphersuites into message", ex);
            }
        }
        return stream.toByteArray();
    }

    private byte[] convertCipherSuites(List<CipherSuite> suiteList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CipherSuite suite : suiteList) {
            try {
                stream.write(suite.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare ClientHelloMessage. Failed to write Ciphersuites into message", ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareProtocolVersion(ClientHelloMessage msg) {
        msg.setProtocolVersion(chooser.getConfig().getHighestProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    private void prepareCompressions(ClientHelloMessage msg) {
        msg.setCompressions(convertCompressions(chooser.getConfig().getSupportedCompressionMethods()));
        LOGGER.debug("Compressions: " + ArrayConverter.bytesToHexString(msg.getCompressions().getValue()));
    }

    private void prepareCompressionLength(ClientHelloMessage msg) {
        msg.setCompressionLength(msg.getCompressions().getValue().length);
        LOGGER.debug("CompressionLength: " + msg.getCompressionLength().getValue());
    }

    private void prepareCipherSuites(ClientHelloMessage msg) {
        msg.setCipherSuites(convertCipherSuites(chooser.getConfig().getDefaultClientSupportedCiphersuites()));
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    private void prepareCipherSuitesLength(ClientHelloMessage msg) {
        msg.setCipherSuiteLength(msg.getCipherSuites().getValue().length);
        LOGGER.debug("CipherSuitesLength: " + msg.getCipherSuiteLength().getValue());
    }

    private boolean hasHandshakeCookie() {
        return chooser.getContext().getDtlsCookie() != null;
    }

    private void prepareCookie(ClientHelloMessage msg) {
        msg.setCookie(chooser.getDtlsCookie());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

    private void prepareCookieLength(ClientHelloMessage msg) {
        msg.setCookieLength((byte) msg.getCookie().getValue().length);
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }
}
