/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * This handler processes the HelloRetryRequest messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.1.4
 * 
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class HelloRetryRequestHandler extends HandshakeMessageHandler<HelloRetryRequestMessage> {

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
        return new HelloRetryRequestSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HelloRetryRequestMessage message) {
        adjustProtocolVersion(message);
        adjustSelectedCiphersuite(message);
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                extension.getHandler(tlsContext).adjustTLSContext(extension);
            }
        }
    }

    private void adjustProtocolVersion(HelloRetryRequestMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        tlsContext.setSelectedProtocolVersion(version);
        LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
    }

    private void adjustSelectedCiphersuite(HelloRetryRequestMessage message) {
        CipherSuite suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        tlsContext.setSelectedCipherSuite(suite);
        LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
    }

}
