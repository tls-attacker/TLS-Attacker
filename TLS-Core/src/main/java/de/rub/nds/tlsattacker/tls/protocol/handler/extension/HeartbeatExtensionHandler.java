/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.HeartbeatExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.HeartbeatExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.HeartbeatExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatExtensionHandler extends ExtensionHandler<HeartbeatExtensionMessage> {

    public HeartbeatExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    protected void adjustTLSContext(HeartbeatExtensionMessage message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public HeartbeatExtensionParser getParser(byte[] message, int pointer) {
        return new HeartbeatExtensionParser(pointer, message);
    }

    @Override
    public HeartbeatExtensionPreparator getPreparator(HeartbeatExtensionMessage message) {
        return new HeartbeatExtensionPreparator(context, message);
    }

    @Override
    public HeartbeatExtensionSerializer getSerializer(HeartbeatExtensionMessage message) {
        return new HeartbeatExtensionSerializer(message);
    }
}
