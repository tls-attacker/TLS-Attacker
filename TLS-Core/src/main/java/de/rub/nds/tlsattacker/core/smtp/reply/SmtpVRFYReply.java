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
import de.rub.nds.tlsattacker.core.smtp.preparator.VRFYReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
public class SmtpVRFYReply extends SmtpReply {
    private String description;

    // these are lists because in a 553 reply, there may be multiple usernames/mailboxes:
    private List<String> fullNames = new LinkedList<>();
    private List<String> mailboxes = new LinkedList<>();

    public SmtpVRFYReply() {}

    // For non-553 reply codes:
    public SmtpVRFYReply(int replyCode, String description, String fullName, String mailbox) {
        setReplyCode(replyCode);
        setDescription(description);
        addFullName(fullName);
        addMailbox(mailbox);
    }

    /*
       For 553-reply codes. Technically, replyCode should always be 553 but omitting it may cause
       misuse of the constructor.
    */
    public SmtpVRFYReply(
            int replyCode, String description, List<String> fullNames, List<String> mailboxes) {
        setReplyCode(replyCode);
        setDescription(description);
        setFullNames(fullNames);
        setMailboxes(mailboxes);
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    @Override
    public VRFYReplyPreparator getPreparator(SmtpContext context) {
        return new VRFYReplyPreparator(context, this);
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
}
