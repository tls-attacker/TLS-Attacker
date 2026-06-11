/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

/**
 * Most, but not all, POP3 commands can have message-numbers. In order to prevent redundant parsers
 * for all the message-number containing commands and because of class/casting restrictions of Java,
 * this interface is used to cast generic classes to pseudo message-number classes. This
 * significantly reduces the amount of files and code necessary for command parsing.
 */
public interface Pop3MessageNumber {
    void setMessageNumber(Integer messageNumber);

    Integer getMessageNumber();
}
