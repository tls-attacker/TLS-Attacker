/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpEXPNReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpVRFYReply;

import java.io.InputStream;
import java.util.List;

public class EXPNReplyParser extends SmtpReplyParser<SmtpEXPNReply> {

    public EXPNReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    // for now just duplicated code from VRFYReplyParser:
    @Override
    public void parse(SmtpEXPNReply reply) {
        List<String> lines = readWholeReply();

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);

            if (i == 0) this.parseReplyCode(reply, line);
            else this.checkReplyCodeConsistency(reply.getReplyCode(), line.substring(0, 3));

            if (line.length() <= 4) continue;

            int mailboxStartIndex = findMailboxStartIndex(line.substring(4)) + 4;
            if (mailboxStartIndex != -1) {
                String username = line.substring(4, mailboxStartIndex - 1); // minus delimiter
                String mailbox = line.substring(mailboxStartIndex);

                // defaults to adding an empty username if not present:
                reply.addUsernameAndMailbox(username, mailbox);
            }
        }
    }

    public int findMailboxStartIndex(String str) {
        int start = 0;
        int end = -1;
        while (end < str.length()) {
            while (start < str.length() && str.charAt(start) != '<') start++;

            end = start;
            while (end < str.length() && str.charAt(end) != '>') end++;

            // check for bare minimum requirements for identifying mailboxes:
            if (end < str.length()
                    && str.substring(start, end + 1).contains("@")
                    && end == str.length() - 1) return start;
        }

        return -1;
    }
}
