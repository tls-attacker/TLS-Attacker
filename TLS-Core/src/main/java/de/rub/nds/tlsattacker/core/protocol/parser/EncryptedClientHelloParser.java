/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedClientHelloMessage;
import java.io.InputStream;

public class EncryptedClientHelloParser extends CoreClientHelloParser<EncryptedClientHelloMessage> {

    /**
     * Constructor for the Parser class
     *
     * @param stream InputStream that contains data to parse
     * @param tlsContext Context of this connection
     */
    public EncryptedClientHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }
}
