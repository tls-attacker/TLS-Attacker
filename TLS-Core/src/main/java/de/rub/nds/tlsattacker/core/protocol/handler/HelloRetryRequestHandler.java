/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the HelloRetryRequest messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.1.4
 */
public class HelloRetryRequestHandler extends HandshakeMessageHandler<HelloRetryRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HelloRetryRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HelloRetryRequestParser getParser(byte[] message, int pointer) {
        return new HelloRetryRequestParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public HelloRetryRequestPreparator getPreparator(HelloRetryRequestMessage message) {
        return new HelloRetryRequestPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public HelloRetryRequestSerializer getSerializer(HelloRetryRequestMessage message) {
        return new HelloRetryRequestSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(HelloRetryRequestMessage message) {
        adjustProtocolVersion(message);
        adjustSelectedCiphersuite(message);
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = HandshakeMessageType.HELLO_RETRY_REQUEST;
                if (extension instanceof KeyShareExtensionMessage) {
                    handshakeMessageType = HandshakeMessageType.CLIENT_HELLO;
                }
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                        extension.getExtensionTypeConstant(), handshakeMessageType);
                handler.adjustTLSContext(extension);
            }
        }
    }

    private void adjustProtocolVersion(HelloRetryRequestMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        if (version != null) {
            tlsContext.setSelectedProtocolVersion(version);
            LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                    + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustSelectedCiphersuite(HelloRetryRequestMessage message) {
        CipherSuite suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        tlsContext.setSelectedCipherSuite(suite);
        if (suite != null) {
            LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
        } else {
            LOGGER.warn("Could not determine selected CipherSuite. Not Adjusting Context");
        }
    }

}
