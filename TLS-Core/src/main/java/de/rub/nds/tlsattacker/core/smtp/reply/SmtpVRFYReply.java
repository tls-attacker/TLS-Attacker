/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYCommandParser;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class SmtpVRFYReply extends SmtpReply {
    private String statusCode;
    private String description;

    // these are lists because in a 553 reply, there may be multiple usernames/mailboxes:
    private List<String> fullNames = new LinkedList<>();
    private List<String> mailboxes = new LinkedList<>();

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    public String getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(String statusCode) {
        this.statusCode = statusCode;
    }

    public List<String> getFullNames() {
        return fullNames;
    }

    public void setFullNames(List<String> fullNames) {
        this.fullNames = fullNames;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getMailboxes() {
        return mailboxes;
    }

    public void setMailboxes(List<String> mailboxes) {
        this.mailboxes = mailboxes;
    }

    public void addMailbox(String mailbox) {
        this.mailboxes.add(mailbox);
    }

    public void addFullName(String fullName) {
        this.fullNames.add(fullName);
    }
}
