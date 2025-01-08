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

    private static final Logger LOGGER = LogManager.getLogger();

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
        String firstLine = parseSingleLine();
        parseReplyIndicator(reply, firstLine);
        parseHumanReadableMessage(reply, firstLine);

        List<String> lines = new LinkedList<>();
        try (BufferedInputStream stream = new BufferedInputStream(this.getStream())) {
            stream.mark(Integer.MAX_VALUE);

            String line = "";
            while(!line.equals(".\r\n")) {
                StringBuilder sb = new StringBuilder();
                int c = stream.read();

                while(c != 10) { // 10 is LF
                    sb.append((char) c);
                    c = stream.read();
                }

                line = sb.toString();
                lines.add(line);
            }

            stream.reset();
        } catch (IOException ignored) {
            LOGGER.warn("An IOException occurred while checking for multi-line replies. This is normal behavior if the reply was single-line. If not, the reply is likely malformed.");
        }

        for (String line : lines) {
            String[] parts = line.split(" ");
            if (parts.length == 2) {
                reply.addMessageNumber(parts[0]);
                reply.addMessageOctet(parts[1]);
            }
        }
    }
}
