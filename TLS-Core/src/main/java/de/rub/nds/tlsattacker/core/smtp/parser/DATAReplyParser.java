/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DATAReplyParser extends SmtpReplyParser<SmtpDATAReply> {

    public DATAReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAReply dataReply) {
        List<String> lines = readWholeReply();

        dataReply.setReplyCode(Integer.parseInt(lines.get(0).substring(0, 3)));

        List<String> replyLines = new ArrayList<>();
        for (String line : lines) {
            replyLines.add(line.substring(4));
        }

        dataReply.setReplyLines(replyLines);
    }
}
