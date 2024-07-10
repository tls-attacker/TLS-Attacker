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
import java.util.Arrays;
import java.util.List;

public class DATAReplyParser extends SmtpReplyParser<SmtpDATAReply> {

    public DATAReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAReply dataReply) {
        List<String> lines = parseAllLines();
        // save all possible reply codes
        List<String> replyCodes = Arrays.asList("354", "503", "554");
        if (lines.size() > 1) {
            throw new ParserException(
                    "Could not parse DATAReply. Expected single line reply but got multiple line reply.");
        }

        if (!startsWithAny(lines.get(0), replyCodes)) {
            throw new ParserException(
                    "Could not parse DATAReply. Not a valid reply code or Malformed reply.");
        }

        String[] line = lines.get(0).split(" ", 2);
        if (line.length > 1) {
            dataReply.setDataMessage(line[1]);
        } else {
            dataReply.setDataMessage(" ");
        }
        dataReply.setReplyCode(Integer.parseInt(line[0]));
    }

    private boolean startsWithAny(String line, List<String> replyCodes) {
        for (String code : replyCodes) {
            if (line.startsWith(code)) {
                return true;
            }
        }
        return false;
    }
}
