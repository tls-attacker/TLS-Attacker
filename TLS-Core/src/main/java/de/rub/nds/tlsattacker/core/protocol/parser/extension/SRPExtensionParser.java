/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SRPExtensionParser extends ExtensionParser<SRPExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SRPExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SRPExtensionMessage msg) {
        msg.setSrpIdentifierLength(parseIntField(ExtensionByteLength.SRP_IDENTIFIER_LENGTH));
        msg.setSrpIdentifier(parseByteArrayField(msg.getSrpIdentifierLength().getValue()));
    }
}
