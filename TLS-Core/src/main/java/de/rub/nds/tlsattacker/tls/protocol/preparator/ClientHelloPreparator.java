/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloPreparator extends HelloMessagePreparator<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    private final ClientHelloMessage message;

    public ClientHelloPreparator(TlsContext context, ClientHelloMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        message.setProtocolVersion(context.getConfig().getHighestProtocolVersion().getValue());
        prepareUnixTime();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();
        message.setCompressions(convertCompressions(context.getConfig().getSupportedCompressionMethods()));
        message.setCompressionLength(message.getCompressions().getValue().length);
        message.setCipherSuites(convertCipherSuites(context.getConfig().getSupportedCiphersuites()));
        message.setCipherSuiteLength(message.getCipherSuites().getValue().length);
        if (context.getDtlsHandshakeCookie() != null) {
            message.setCookie(context.getDtlsHandshakeCookie());
            message.setCookieLength((byte) message.getCookie().getValue().length);
        }
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareSessionID() {
        if (context.getSessionID() == null) {
            message.setSessionId(context.getConfig().getSessionId());
        } else {
            message.setSessionId(context.getSessionID());
        }
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

}
