/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
        prepareCompressionMethod();
        if (!chooser.getConfig().getHighestProtocolVersion().isSSL()
            || (chooser.getConfig().getHighestProtocolVersion().isSSL()
                && chooser.getConfig().isAddExtensionsInSSL())) {
            prepareExtensions();
            prepareExtensionLength();
        }
    }

    private void prepareCipherSuite() {
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setSelectedCipherSuite(chooser.getConfig().getDefaultSelectedCipherSuite().getByteValue());
        } else {
            CipherSuite selectedSuite = null;
            for (CipherSuite suite : chooser.getConfig().getDefaultServerSupportedCipherSuites()) {
                if (chooser.getClientSupportedCipherSuites().contains(suite)) {
                    selectedSuite = suite;
                    break;
                }
            }
            if (selectedSuite == null) {
                selectedSuite = chooser.getConfig().getDefaultSelectedCipherSuite();
                LOGGER.warn("No CipherSuites in common, falling back to defaultSelectedCipherSuite");
            }
            msg.setSelectedCipherSuite(selectedSuite.getByteValue());
        }
        LOGGER
            .debug("SelectedCipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
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
                selectedCompressionMethod = chooser.getConfig().getDefaultSelectedCompressionMethod();
                LOGGER.warn("No CompressionMethod in common, falling back to defaultSelectedCompressionMethod");
            }
            msg.setSelectedCompressionMethod(selectedCompressionMethod.getValue());
        }
        LOGGER.debug("SelectedCompressionMethod: " + msg.getSelectedCompressionMethod().getValue());
    }

    private void prepareSessionID() {
        if (chooser.getConfig().getHighestProtocolVersion().isTLS13()) {
            msg.setSessionId(chooser.getClientSessionId());
        } else {
            msg.setSessionId(chooser.getServerSessionId());
        }
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = chooser.getConfig().getHighestProtocolVersion();
        if (chooser.getConfig().getHighestProtocolVersion().isTLS13()) {
            ourVersion = ProtocolVersion.TLS12;
        }

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
