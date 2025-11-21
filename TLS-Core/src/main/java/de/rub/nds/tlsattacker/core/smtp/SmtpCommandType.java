/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.*;
import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.*;
import java.util.function.Supplier;

public enum SmtpCommandType {
    // < > does not denote real command keywords, but this is better in case someone wants string
    // representation
    EHLO("EHLO", SmtpEHLOCommand::new, SmtpEHLOReply::new),
    HELO("HELO", SmtpHELOCommand::new, SmtpEHLOReply::new),
    NOOP("NOOP", SmtpNOOPCommand::new, SmtpNOOPReply::new),
    AUTH("AUTH", SmtpAUTHCommand::new, SmtpAUTHReply::new),
    AUTH_CREDENTIALS(
            "<AUTHCREDENTIALS>", SmtpAUTHCredentialsCommand::new, SmtpAUTHCredentialsReply::new),
    EXPN("EXPN", SmtpEXPNCommand::new, SmtpEXPNReply::new),
    VRFY("VRFY", SmtpVRFYCommand::new, SmtpVRFYReply::new),
    MAIL("MAIL", SmtpMAILCommand::new, SmtpMAILReply::new),
    RSET("RSET", SmtpRSETCommand::new, SmtpRSETReply::new),
    DATA("DATA", SmtpDATACommand::new, SmtpDATAReply::new),
    DATA_CONTENT("<DATACONTENT>", SmtpDATAContentCommand::new, SmtpDATAContentReply::new),
    RCPT("RCPT", SmtpRCPTCommand::new, SmtpRCPTReply::new),
    HELP("HELP", SmtpHELPCommand::new, SmtpHELPReply::new),
    QUIT("QUIT", SmtpQUITCommand::new, SmtpQUITReply::new),
    STARTTLS("STARTTLS", SmtpSTARTTLSCommand::new, SmtpSTARTTLSReply::new),
    INITIAL_GREETING("<INITIALGREETING>", SmtpInitialGreetingDummy::new, SmtpInitialGreeting::new),
    UNKNOWN("<UNKNOWN>", SmtpUnknownCommand::new, SmtpUnknownReply::new),
    CUSTOM("<CUSTOM>", null, null);

    private final String keyword;
    private final Supplier<SmtpCommand> commandSupplier;
    private final Supplier<SmtpReply> replySupplier;

    SmtpCommandType(
            String keyword,
            Supplier<SmtpCommand> commandSupplier,
            Supplier<SmtpReply> replySupplier) {
        this.keyword = keyword;
        this.commandSupplier = commandSupplier;
        this.replySupplier = replySupplier;
    }

    public String getKeyword() {
        return keyword;
    }

    public SmtpCommand createCommand() {
        return commandSupplier.get();
    }

    public SmtpReply createReply() {
        return replySupplier.get();
    }

    public static SmtpCommandType fromKeyword(String keyword) {
        for (SmtpCommandType type : values()) {
            if (type.keyword != null && type.keyword.equals(keyword)) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
