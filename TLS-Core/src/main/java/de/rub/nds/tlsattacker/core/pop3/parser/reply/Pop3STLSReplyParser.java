/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3STLSReply;
import java.io.InputStream;

public class Pop3STLSReplyParser extends Pop3GenericReplyParser<Pop3STLSReply> {
    public Pop3STLSReplyParser(InputStream stream) {
        super(stream);
    }
}
