/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECPointFormatExtensionHandler extends ExtensionHandler<ECPointFormatExtensionMessage> {

    public ECPointFormatExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    protected void adjustTLSContext(ECPointFormatExtensionMessage message) {
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
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new ECPointFormatExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(ECPointFormatExtensionMessage message) {
        return new ECPointFormatExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(ECPointFormatExtensionMessage message) {
        return new ECPointFormatExtensionSerializer(message);
    }

}
