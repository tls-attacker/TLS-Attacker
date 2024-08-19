/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class VRFYReplyParser extends SmtpReplyParser<SmtpVRFYReply> {

    public VRFYReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(SmtpVRFYReply reply) {
        List<String> lines = readWholeReply();
        List<String> replyLines = new LinkedList<>();

        for (String line : lines) {
            // extract as much as we can:
            String possibleReplyCode = line.substring(0, 3);

            reply.setReplyCode(Integer.parseInt(possibleReplyCode));

            // excluding the reply code:
            replyLines.add(line.substring(4));

            List<Integer[]> mailboxIndices = getMailboxIndices(line);
            addMailboxes(reply, line, mailboxIndices);
        }

        reply.setLineContents(replyLines);
    }

    // str only saved as mailbox if it has <...@...>
    public void addMailboxes(SmtpVRFYReply reply, String str, List<Integer[]> mailboxIndices) {
        for (Integer[] indices : mailboxIndices) {
            String mailbox = str.substring(indices[0] + 1, indices[1]);
            if (mailbox.contains("@")) reply.addMailbox(mailbox);
        }
    }

    // finds enclosed mailboxes:
    public List<Integer[]> getMailboxIndices(String str) {
        List<Integer[]> possibleMailboxIndices = new LinkedList<>();

        int i = 0;
        while (i < str.length()) {
            while (i < str.length() && str.charAt(i) != '<') i++;

            int j = i;
            while (j < str.length() && str.charAt(j) != '>') j++;

            if (j < str.length()) {
                possibleMailboxIndices.add(new Integer[] {i, j});
                i = j + 1;
            }
        }

        return possibleMailboxIndices;
    }
}
