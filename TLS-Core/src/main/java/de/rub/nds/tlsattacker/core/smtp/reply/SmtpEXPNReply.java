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
import de.rub.nds.tlsattacker.core.smtp.parser.EXPNReplyParser;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.EXPNReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.VRFYCommandPreparator;

import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class SmtpEXPNReply extends SmtpReply {
    private String description;

    private List<String> fullNames = new LinkedList<>();
    private List<String> mailboxes = new LinkedList<>();

    private boolean mailboxesAreEnclosed = false;

    public SmtpEXPNReply() {}

    public SmtpEXPNReply(
            int replyCode, String description, List<String> fullNames, List<String> mailboxes, boolean mailboxesAreEnclosed) {
        setReplyCode(replyCode);
        setDescription(description);
        setFullNames(fullNames);
        setMailboxes(mailboxes);
        if (mailboxesAreEnclosed) markMailboxesAsEnclosed();
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new EXPNReplyParser(stream);
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return new EXPNReplyPreparator(context, this);
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
        if (description != null) this.description = description;
    }

    public List<String> getMailboxes() {
        return mailboxes;
    }

    public void setMailboxes(List<String> mailboxes) {
        this.mailboxes = mailboxes;
    }

    public void addMailbox(String mailbox) {
        if (mailbox != null) this.mailboxes.add(mailbox);
    }

    public void addFullName(String fullName) {
        if (fullName != null) this.fullNames.add(fullName);
    }

    public void markMailboxesAsEnclosed() {
        this.mailboxesAreEnclosed = true;
    }

    public boolean mailboxesAreEnclosed() {
        return mailboxesAreEnclosed;
    }
}
