/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Pop3 replies from InputStream. The default implementation only parses the status code and
 * the human readable message. If more complex parsing is needed, the parse method can be
 * overridden. Multiline replies begin with the status indicator in the first line and every line
 * terminated with <CRLF> the last line is just a . followed by <CRLF>. The response is ended by
 * encountering following sequence: <CRLF>.<CRLF>
 *
 * @param <ReplyT> specific reply class
 */
public abstract class Pop3ReplyParser<ReplyT extends Pop3Reply> extends Pop3MessageParser<ReplyT> {

    public Pop3ReplyParser(InputStream stream) {
        super(stream);
    }

    public List<String> readWholeReply() {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = parseSingleLine()) != null) {
            lines.add(line);
            if (isEndOfReply(line)) {
                break;
            }
        }

        if (!lines.get(lines.size() - 1).matches("^\\.")) {
            throw new ParserException(
                    "No termination octet has been sent: " + lines.get(lines.size() - 1));
        }

        return lines;
    }

    public void parseReplyIndicator(ReplyT reply, String line) {

        if (line.matches("^\\+OK.*")) {
            reply.setStatusIndicator("+OK");
        } else if (line.matches("^-ERR.*")) {
            reply.setStatusIndicator("-ERR");
        }
    }

    public boolean isEndOfReply(String line) {
        return line.matches("^\\.");
    }

    public abstract void parse(ReplyT reply);
}
