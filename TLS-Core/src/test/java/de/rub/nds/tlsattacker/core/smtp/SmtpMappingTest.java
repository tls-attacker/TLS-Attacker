/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpUnknownCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
import java.lang.reflect.InvocationTargetException;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.ReflectionsException;

public class SmtpMappingTest {
    /**
     * Test that every subclass of SmtpCommand is properly mapped to a reply via SmtpMappingUtil.
     * Using reflection here is not ideal, but it's the best way to ensure that every command is
     * mapped for new developers.
     */
    @Test
    public void testEveryCommandIsMapped() {
        // Use Reflections to find all subclasses of SmtpCommand
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.smtp");
        Set<Class<? extends SmtpCommand>> commandClasses =
                reflections.getSubTypesOf(SmtpCommand.class);

        for (Class<? extends SmtpCommand> commandClass : commandClasses) {
            try {
                // Instantiate command
                SmtpCommand command = commandClass.getDeclaredConstructor().newInstance();

                // Call getReplyForCommand and assert the reply is not null
                SmtpReply reply = SmtpMappingUtil.getMatchingReply(command);
                if (command instanceof SmtpUnknownCommand) {
                    continue;
                }
                assertFalse(
                        reply instanceof SmtpUnknownReply,
                        "Command for "
                                + commandClass.getSimpleName()
                                + " should not be unknown. If you see this message, you need to implement a command for this reply AND link them via SmtpMappingUtil.");
            } catch (ReflectionsException
                    | NoSuchMethodException
                    | InstantiationException
                    | IllegalAccessException
                    | InvocationTargetException e) {
                Assertions.fail(
                        "Failed to instantiate command or get reply for "
                                + commandClass.getSimpleName()
                                + ": "
                                + e.getMessage());
            }
        }
    }
    /**
     * Test that every subclass of SmtpReply is properly mapped to a command via SmtpMappingUtil.
     * Using reflection here is not ideal, but it's the best way to ensure that every command is
     * mapped for new developers.
     */
    @Test
    public void testEveryReplyIsMapped() {
        // Use Reflections to find all subclasses of SmtpCommand
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.smtp");
        Set<Class<? extends SmtpReply>> replyClasses = reflections.getSubTypesOf(SmtpReply.class);

        for (Class<? extends SmtpReply> replyClass : replyClasses) {
            try {
                // Instantiate command
                SmtpReply reply = replyClass.getDeclaredConstructor().newInstance();

                // Call getReplyForCommand and assert the reply is not null
                SmtpCommand command = SmtpMappingUtil.getMatchingCommand(reply);
                if (reply instanceof SmtpUnknownReply) {
                    continue;
                }
                assertFalse(
                        command instanceof SmtpUnknownCommand,
                        "Command for "
                                + replyClass.getSimpleName()
                                + " should not be unknown. If you see this message, you need to implement a command for this reply AND link them via SmtpMappingUtil.");
            } catch (ReflectionsException
                    | NoSuchMethodException
                    | InstantiationException
                    | IllegalAccessException
                    | InvocationTargetException e) {
                Assertions.fail(
                        "Failed to instantiate command or get reply for "
                                + replyClass.getSimpleName()
                                + ": "
                                + e.getMessage());
            }
        }
    }
}
