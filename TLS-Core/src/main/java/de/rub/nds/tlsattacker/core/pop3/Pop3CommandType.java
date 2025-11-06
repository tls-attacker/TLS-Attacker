/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.*;
import java.util.function.Supplier;

/**
 * Enum that captures the relationship between POP3 command keywords, command classes, and reply
 * classes.
 */
public enum Pop3CommandType {
    // < > does not denote real command keywords, but this is better in case someone wants string
    // representation
    USER("USER", Pop3USERCommand::new, Pop3USERReply::new),
    PASS("PASS", Pop3PASSCommand::new, Pop3PASSReply::new),
    DELE("DELE", Pop3DELECommand::new, Pop3DELEReply::new),
    LIST("LIST", Pop3LISTCommand::new, Pop3LISTReply::new),
    NOOP("NOOP", Pop3NOOPCommand::new, Pop3NOOPReply::new),
    QUIT("QUIT", Pop3QUITCommand::new, Pop3QUITReply::new),
    RETR("RETR", Pop3RETRCommand::new, Pop3RETRReply::new),
    RSET("RSET", Pop3RSETCommand::new, Pop3RSETReply::new),
    STAT("STAT", Pop3STATCommand::new, Pop3STATReply::new),
    STLS("STLS", Pop3STLSCommand::new, Pop3STLSReply::new),
    INITIAL_GREETING("<INITIALGREETING>", Pop3InitialGreetingDummy::new, Pop3InitialGreeting::new),
    UNKNOWN("<UNKNOWN>", Pop3UnknownCommand::new, Pop3UnknownReply::new),
    CUSTOM("<CUSTOM>", null, null);

    private final String keyword;
    private final Supplier<Pop3Command> commandSupplier;
    private final Supplier<Pop3Reply> replySupplier;

    Pop3CommandType(
            String keyword,
            Supplier<Pop3Command> commandSupplier,
            Supplier<Pop3Reply> replySupplier) {
        this.keyword = keyword;
        this.commandSupplier = commandSupplier;
        this.replySupplier = replySupplier;
    }

    public String getKeyword() {
        return keyword;
    }

    public Pop3Command createCommand() {
        return commandSupplier.get();
    }

    public Pop3Reply createReply() {
        return replySupplier.get();
    }

    public static Pop3CommandType fromKeyword(String keyword) {
        for (Pop3CommandType type : values()) {
            if (type.keyword != null && type.keyword.equals(keyword)) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
