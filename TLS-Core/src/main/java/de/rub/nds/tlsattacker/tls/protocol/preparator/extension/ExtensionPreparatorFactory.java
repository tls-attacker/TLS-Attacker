/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExtensionPreparatorFactory {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    public static ExtensionPreparator getExtensionPreparator(TlsContext context, ExtensionMessage message) {
        try {
            return message.getExtensionPreparator();
        } catch (UnsupportedOperationException ex) {
            LOGGER.error("Preparator not implemented yet for " + message.getExtensionType().toString());
            throw new PreparationException("Could not prepare " + message.getExtensionType().toString(), ex);
        }
    }
}
