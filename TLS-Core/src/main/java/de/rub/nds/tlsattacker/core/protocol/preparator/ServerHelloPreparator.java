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
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloPreparator extends HelloMessagePreparator<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerHelloMessage msg;

    public ServerHelloPreparator(Chooser chooser, ServerHelloMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ServerHelloMessage");
        prepareProtocolVersion();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();

        prepareCipherSuite();
        if (!chooser.getSelectedProtocolVersion().isTLS13()) {
            prepareCompressionMethod();
        }
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareCipherSuite() {
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setSelectedCipherSuite(chooser.getConfig().getDefaultSelectedCipherSuite().getByteValue());
        } else {
            CipherSuite selectedSuite = null;
            for (CipherSuite suite : chooser.getConfig().getDefaultServerSupportedCiphersuites()) {
                if (chooser.getClientSupportedCiphersuites().contains(suite)) {
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
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setSelectedCompressionMethod(chooser.getConfig().getDefaultSelectedCompressionMethod().getValue());
        } else {
            CompressionMethod selectedCompressionMethod = null;
            for (CompressionMethod method : chooser.getConfig().getDefaultServerSupportedCompressionMethods()) {
                if (chooser.getClientSupportedCompressions().contains(method)) {
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
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            msg.setSessionId(new byte[0]);
        } else {
            msg.setSessionId(chooser.getServerSessionId());
        }
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = chooser.getConfig().getHighestProtocolVersion();
        ProtocolVersion clientVersion = chooser.getHighestClientProtocolVersion();
        int intRepresentationOurVersion = ourVersion.getValue()[0] * 0x100 + ourVersion.getValue()[1];
        int intRepresentationClientVersion = clientVersion.getValue()[0] * 0x100 + clientVersion.getValue()[1];
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setProtocolVersion(ourVersion.getValue());
        } else {
            if (chooser.getHighestClientProtocolVersion().isDTLS()
                    && chooser.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want dtls
                if (intRepresentationClientVersion <= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            }
            if (!chooser.getHighestClientProtocolVersion().isDTLS()
                    && !chooser.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want tls
                if (intRepresentationClientVersion >= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            } else {
                msg.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
            }
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }
}
