/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3LISTReply;
import java.io.*;
import java.util.LinkedList;
import java.util.List;

public class Pop3LISTReplyParser extends Pop3ReplyParser<Pop3LISTReply> {

    public Pop3LISTReplyParser(InputStream stream) {

        super(new BufferedInputStream(stream));
    }

    @Override
    public void parse(Pop3LISTReply reply) {
        String firstLine = parseSingleLine();
        parseReplyIndicator(reply, firstLine);
        parseHumanReadableMessage(reply, firstLine);

        if (reply.isSingleLine()) return; //FIXME: LIST [n] prompts a single line everytime - bring Pop3Context here

        List<String> lines = new LinkedList<>();
        if (reply.getStatusIndicator().equals("+OK")) {
            try {
                String line;
                while ((line = parseSingleLine()) != null) {
                    lines.add(line);
                    if (isEndOfLIST(line)) {
                        break;
                    }
                }
            } catch (EndOfStreamException e) {
                LOGGER.warn("End of stream reached before end of LIST reply.");
                throw new ParserException("LIST reply not complete.");
            }
        }
        for (String line : lines) {
            String[] parts = line.split(" ");
            if (parts.length == 2) {
                reply.addMessageNumber(toInteger(parts[0]));
                reply.addMessageSize(toInteger(parts[1]));
            }
        }
    }

    private boolean isEndOfLIST(String line) {
        return line.equals(".");
    }
}
