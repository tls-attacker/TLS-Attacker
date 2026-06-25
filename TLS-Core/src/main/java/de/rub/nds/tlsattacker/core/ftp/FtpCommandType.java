/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp;

import de.rub.nds.tlsattacker.core.ftp.command.*;
import de.rub.nds.tlsattacker.core.ftp.reply.*;
import java.util.function.Supplier;

/**
 * Captures the relationship between FTP command keywords, command classes, and reply classes. Only
 * the keywords required for the RFC 4217 control-connection STARTTLS upgrade are modelled.
 */
public enum FtpCommandType {
    // < > does not denote real command keywords, but this is better in case someone wants string
    // representation
    AUTH("AUTH", FtpAUTHCommand::new, FtpAUTHReply::new),
    INITIAL_GREETING("<INITIALGREETING>", FtpInitialGreetingDummy::new, FtpInitialGreeting::new),
    UNKNOWN("<UNKNOWN>", FtpUnknownCommand::new, FtpUnknownReply::new),
    CUSTOM("<CUSTOM>", null, null);

    private final String keyword;
    private final Supplier<FtpCommand> commandSupplier;
    private final Supplier<FtpReply> replySupplier;

    FtpCommandType(
            String keyword,
            Supplier<FtpCommand> commandSupplier,
            Supplier<FtpReply> replySupplier) {
        this.keyword = keyword;
        this.commandSupplier = commandSupplier;
        this.replySupplier = replySupplier;
    }

    public String getKeyword() {
        return keyword;
    }

    public FtpCommand createCommand() {
        return commandSupplier.get();
    }

    public FtpReply createReply() {
        return replySupplier.get();
    }

    public static FtpCommandType fromKeyword(String keyword) {
        for (FtpCommandType type : values()) {
            if (type.keyword != null && type.keyword.equals(keyword)) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
