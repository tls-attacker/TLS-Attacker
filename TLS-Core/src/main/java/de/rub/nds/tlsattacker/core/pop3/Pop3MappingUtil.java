package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;

import java.util.HashMap;
import java.util.Map;

public class Pop3MappingUtil {
    public static Pop3Reply getMatchingReply(Pop3Command command) {
        if (command == null) {
            return null;
        }
        if (command instanceof Pop3USERCommand) {
            return new Pop3USERReply();
        } else if (command instanceof Pop3InitialGreetingDummy) {
            return new Pop3InitialGreeting();
        } else if (command instanceof Pop3PASSCommand) {
            return new Pop3PASSReply();
        } else if (command instanceof Pop3DELECommand) {
            return new Pop3DELEReply();
        } else if (command instanceof Pop3LISTCommand) {
            return new Pop3LISTReply();
        } else if (command instanceof Pop3NOOPCommand) {
            return new Pop3NOOPReply();
        } else if (command instanceof Pop3QUITCommand) {
            return new Pop3QUITReply();
        } else if (command instanceof Pop3RETRCommand) {
            return new Pop3RETRReply();
        } else if (command instanceof Pop3RSETCommand) {
            return new Pop3RSETReply();
        } else if (command instanceof Pop3STATCommand) {
            return new Pop3STATReply();
        } else if (command instanceof Pop3STLSCommand) {
            return new Pop3STLSReply();
        } else {
            return new Pop3UnknownReply();
        }
    }

    public static Pop3Command getMatchingCommand(Pop3Reply reply) {
        if(reply == null) {
            return null;
        }
        if (reply instanceof Pop3USERReply) {
            return new Pop3USERCommand();
        } else if (reply instanceof Pop3InitialGreeting) {
            return new Pop3InitialGreetingDummy();
        } else if (reply instanceof Pop3PASSReply) {
            return new Pop3PASSCommand();
        } else if (reply instanceof Pop3DELEReply) {
            return new Pop3DELECommand();
        } else if (reply instanceof Pop3LISTReply) {
            return new Pop3LISTCommand();
        } else if (reply instanceof Pop3NOOPReply) {
            return new Pop3NOOPCommand();
        } else if (reply instanceof Pop3QUITReply) {
            return new Pop3QUITCommand();
        } else if (reply instanceof Pop3RETRReply) {
            return new Pop3RETRCommand();
        } else if (reply instanceof Pop3RSETReply) {
            return new Pop3RSETCommand();
        } else if (reply instanceof Pop3STATReply) {
            return new Pop3STATCommand();
        } else if (reply instanceof Pop3STLSReply) {
            return new Pop3STLSCommand();
        } else {
            return new Pop3UnknownCommand();
        }
    }

    public static Pop3Command getCommandFromCommandName(String commandName) {
        switch (commandName) {
            case "USER":
                return new Pop3USERCommand();
            case "PASS":
                return new Pop3PASSCommand();
            case "DELE":
                return new Pop3DELECommand();
            case "LIST":
                return new Pop3LISTCommand();
            case "NOOP":
                return new Pop3NOOPCommand();
            case "QUIT":
                return new Pop3QUITCommand();
            case "RETR":
                return new Pop3RETRCommand();
            case "RSET":
                return new Pop3RSETCommand();
            case "STAT":
                return new Pop3STATCommand();
            case "STLS":
                return new Pop3STLSCommand();
            default:
                return new Pop3UnknownCommand();
        }
    }
}
