/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.*;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.*;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExtensionSerialiszerFactory {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    public static ExtensionSerializer getExtensionSerialiszer(TlsContext context, ExtensionMessage message) {
        try {
            return message.getExtensionSerializer();
        } catch (UnsupportedOperationException ex) {
            LOGGER.error("Serializer not implemented yet for " + message.getExtensionType().toString());
            throw new PreparationException("Could not prepare " + message.getExtensionType().toString(), ex);
        }
    }
}
