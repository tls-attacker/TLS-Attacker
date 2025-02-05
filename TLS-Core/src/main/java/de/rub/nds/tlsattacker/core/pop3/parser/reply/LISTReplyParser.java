/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3LISTReply;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.LinkedList;
import java.util.List;

public class LISTReplyParser extends Pop3ReplyParser<Pop3LISTReply> {

    public LISTReplyParser(InputStream stream) {
        super(stream);
    }

    /*
    Idea:
    1. Always parse first line.
    2. Try multiline parsing.
        - Multiline present? => Read stream until .CRLF
        - No multiline here? => Exception is thrown and caught.
     */
    @Override
    public void parse(Pop3LISTReply reply) {
        List<String> lines = parseMultiline(reply);

        for (String line : lines) {
            String[] parts = line.split(" ");
            if (parts.length == 2) {
                reply.addMessageNumber(parts[0]);
                reply.addMessageOctet(parts[1]);
            }
        }
    }
}
