/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import java.io.InputStream;

public class ExtendedMasterSecretExtensionParser
        extends ExtensionParser<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    /**
     * Parses the content of the extended master secret extension message. There SHOULDN'T be any
     * data.
     *
     * @param msg The Message that should be parsed
     */
    @Override
    public void parse(ExtendedMasterSecretExtensionMessage msg) {}
}
