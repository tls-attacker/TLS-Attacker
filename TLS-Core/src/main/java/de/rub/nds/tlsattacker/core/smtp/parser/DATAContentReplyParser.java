/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAContentReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class DATAContentReplyParser extends SmtpReplyParser<SmtpDATAContentReply> {

    public DATAContentReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAContentReply dataReply) {
        List<String> lines = readWholeReply();

        dataReply.setReplyCode(Integer.parseInt(lines.get(0).substring(0, 3)));

        List<String> replyLines = new ArrayList<>();
        for (String line : lines) {
            replyLines.add(line.substring(4));
        }

        dataReply.setReplyLines(replyLines);
    }
}
