/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3PASSReply;
import java.io.InputStream;

public class PASSReplyParser extends Pop3GenericReplyParser<Pop3PASSReply> {
    public PASSReplyParser(InputStream stream) {
        super(stream);
    }
}
