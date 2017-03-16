/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.UnknownExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.UnknownExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionHandler extends ExtensionHandler<UnknownExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");

    public UnknownExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    protected void adjustTLSContext(UnknownExtensionMessage message) {

    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new UnknownExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(UnknownExtensionMessage message) {
        return new UnknownExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(UnknownExtensionMessage message) {
        return new UnknownExtensionSerializer(message);
    }

}
