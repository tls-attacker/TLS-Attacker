package de.rub.nds.tlsattacker.core.pop3;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3UnknownCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnknownReply;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.ReflectionsException;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Pop3MappingTest {
    /**
     * Test that every subclass of Pop3Command is properly mapped to a reply via Pop3MappingUtil
     * Using reflection here is not ideal, but it's the best way to ensure that every command is mapped for new developers.
     */
    @Test
    public void testEveryCommandIsMapped() {
        // Use Reflections to find all subclasses of SmtpCommand
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.pop3");
        Set<Class<? extends Pop3Command>> commandClasses = reflections.getSubTypesOf(Pop3Command.class);

        for (Class<? extends Pop3Command> commandClass : commandClasses) {
            try {
                // Instantiate command
                Pop3Command command = commandClass.getDeclaredConstructor().newInstance();

                // Call getReplyForCommand and assert the reply is not null
                Pop3Reply reply = Pop3MappingUtil.getMatchingReply(command);
                 if (command instanceof Pop3UnknownCommand) {
                    continue;
                }
                assertFalse(reply instanceof Pop3UnknownReply, "Reply for " + commandClass.getSimpleName() + " should not be unknown. If you see this message, you need to implement a reply for this command AND link them via Pop3MappingUtil.");
            } catch (ReflectionsException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                Assertions.fail("Failed to instantiate command or get reply for " + commandClass.getSimpleName() + ": " + e.getMessage());
            }
        }
    }/**
     * Test that every subclass of Pop3Reply is properly mapped to a command via Pop3MappingUtil
     * Using reflection here is not ideal, but it's the best way to ensure that every command is mapped for new developers.
     */
    @Test
    public void testEveryReplyIsMapped() {
        // Use Reflections to find all subclasses of SmtpCommand
        Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.pop3");
        Set<Class<? extends Pop3Reply>> replyClasses = reflections.getSubTypesOf(Pop3Reply.class);

        for (Class<? extends Pop3Reply> replyClass : replyClasses) {
            try {
                // Instantiate command
                Pop3Reply reply = replyClass.getDeclaredConstructor().newInstance();

                // Call getReplyForCommand and assert the reply is not null
                Pop3Command command = Pop3MappingUtil.getMatchingCommand(reply);
                if (reply instanceof Pop3UnknownReply) {
                    continue;
                }
                assertFalse(command instanceof Pop3UnknownCommand, "Reply for " + replyClass.getSimpleName() + " should not be unknown. If you see this message, you need to implement a reply for this command AND link them via Pop3MappingUtil.");
            } catch (ReflectionsException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                Assertions.fail("Failed to instantiate command or get reply for " + replyClass.getSimpleName() + ": " + e.getMessage());
            }
        }
    }
}
