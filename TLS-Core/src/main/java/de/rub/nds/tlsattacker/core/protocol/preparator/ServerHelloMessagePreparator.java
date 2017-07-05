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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public class ServerHelloMessagePreparator<T extends ServerHelloMessage> extends HelloMessagePreparator<HelloMessage> {

    private final ServerHelloMessage msg;

    public ServerHelloMessagePreparator(TlsContext context, ServerHelloMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ServerHelloMessage");
        prepareProtocolVersion();
        prepareUnixTime();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();
        prepareCipherSuite();
        prepareCompressionMethod();
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareCipherSuite() {
        if (context.getConfig().isEnforceSettings()) {
            msg.setSelectedCipherSuite(context.getConfig().getSupportedCiphersuites().get(0).getByteValue());
        } else {
            CipherSuite selectedSuite = null;
            for (CipherSuite suite : context.getConfig().getSupportedCiphersuites()) {
                if (context.getClientSupportedCiphersuites().contains(suite)) {
                    selectedSuite = suite;
                    break;
                }
            }
            if (selectedSuite == null) {
                throw new WorkflowExecutionException("No Ciphersuites in common");
            }
            msg.setSelectedCipherSuite(selectedSuite.getByteValue());
        }
        LOGGER.debug("SelectedCipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }

    private void prepareCompressionMethod() {
        if (context.getConfig().isEnforceSettings()) {
            msg.setSelectedCompressionMethod(context.getConfig().getSupportedCompressionMethods().get(0).getValue());
        } else {
            CompressionMethod selectedCompressionMethod = null;
            for (CompressionMethod method : context.getConfig().getSupportedCompressionMethods()) {
                if (context.getClientSupportedCompressions().contains(method)) {
                    selectedCompressionMethod = method;
                    break;
                }
            }
            if (selectedCompressionMethod == null) {
                throw new WorkflowExecutionException("No Compression in common");
            }
            msg.setSelectedCompressionMethod(selectedCompressionMethod.getValue());
        }
        LOGGER.debug("SelectedCompressionMethod: " + msg.getSelectedCompressionMethod().getValue());
    }

    private void prepareSessionID() {
        if (context.getConfig().getSessionId().length > 0) {
            msg.setSessionId(context.getConfig().getSessionId());
        } else {
            msg.setSessionId(ArrayConverter
                    .hexStringToByteArray("f727d526b178ecf3218027ccf8bb125d572068220000ba8c0f774ba7de9f5cdb"));
        }
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = context.getConfig().getHighestProtocolVersion();
        ProtocolVersion clientVersion = context.getHighestClientProtocolVersion();
        int intRepresentationOurVersion = ourVersion.getValue()[0] * 0x100 + ourVersion.getValue()[1];
        int intRepresentationClientVersion = clientVersion.getValue()[0] * 0x100 + clientVersion.getValue()[1];
        if (context.getConfig().isEnforceSettings()) {
            msg.setProtocolVersion(ourVersion.getValue());
        } else {
            if (context.getHighestClientProtocolVersion().isDTLS()
                    && context.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want dtls
                if (intRepresentationClientVersion <= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            }
            if (!context.getHighestClientProtocolVersion().isDTLS()
                    && !context.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want tls
                if (intRepresentationClientVersion >= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            } else {
                if (context.getConfig().isFuzzingMode()) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    throw new WorkflowExecutionException("TLS/DTLS Mismatch");
                }
            }
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }
}
