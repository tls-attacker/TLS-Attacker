package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.*;

public class SmtpMappingUtil {

    /**
     * Given a command return an instance of the Reply object expected fpr ot. Raises an exception
     * when a command is not implemented.
     *
     * @param command The command for which to get the expected reply
     * @return The expected reply object
     */
    public static SmtpReply getMatchingReply(SmtpCommand command) {
        if (command == null) {
            return null;
        }
        if (command instanceof SmtpEHLOCommand || command instanceof SmtpHELOCommand) {
            // HELO's reply is a special case of EHLO's reply without any extensions - this just
            // reuses code
            return new SmtpEHLOReply();
        } else if (command instanceof SmtpNOOPCommand) {
            return new SmtpNOOPReply();
        } else if (command instanceof SmtpAUTHCommand) {
            return new SmtpAUTHReply();
        } else if (command instanceof SmtpEXPNCommand) {
            return new SmtpEXPNReply();
        } else if (command instanceof SmtpVRFYCommand) {
            return new SmtpVRFYReply();
        } else if (command instanceof SmtpMAILCommand) {
            return new SmtpMAILReply();
        } else if (command instanceof SmtpRSETCommand) {
            return new SmtpRSETReply();
        } else if (command instanceof SmtpInitialGreetingDummy) {
            return new SmtpInitialGreeting();
        } else if (command instanceof SmtpDATACommand) {
            return new SmtpDATAReply();
        } else if (command instanceof SmtpRCPTCommand) {
            return new SmtpRCPTReply();
        } else if (command instanceof SmtpDATAContentCommand) {
            return new SmtpDATAContentReply();
        } else if (command instanceof SmtpHELPCommand) {
            return new SmtpHELPReply();
        } else if (command instanceof SmtpQUITCommand) {
            return new SmtpQUITReply();
        } else if (command instanceof SmtpSTARTTLSCommand) {
            return new SmtpSTARTTLSReply();
        } else {
            return new SmtpUnknownReply();
        }
    }

    public static SmtpCommand getMatchingCommand(SmtpReply reply) {
        if (reply == null) {
            return null;
        }
        if (reply instanceof SmtpEHLOReply) {
            return new SmtpEHLOCommand();
        } else if (reply instanceof SmtpInitialGreeting) {
            return new SmtpInitialGreetingDummy();
        } else if (reply instanceof SmtpDATAContentReply) {
            return new SmtpDATAContentCommand();
        } else if (reply instanceof SmtpNOOPReply) {
            return new SmtpNOOPCommand();
        } else if (reply instanceof SmtpAUTHReply) {
            return new SmtpAUTHCommand();
        } else if (reply instanceof SmtpEXPNReply) {
            return new SmtpEXPNCommand();
        } else if (reply instanceof SmtpVRFYReply) {
            return new SmtpVRFYCommand();
        } else if (reply instanceof SmtpMAILReply) {
            return new SmtpMAILCommand();
        } else if (reply instanceof SmtpRSETReply) {
            return new SmtpRSETCommand();
        } else if (reply instanceof SmtpDATAReply) {
            return new SmtpDATACommand();
        } else if (reply instanceof SmtpRCPTReply) {
            return new SmtpRCPTCommand();
        } else if (reply instanceof SmtpHELPReply) {
            return new SmtpHELPCommand();
        } else if (reply instanceof SmtpQUITReply) {
            return new SmtpQUITCommand();
        } else if (reply instanceof SmtpSTARTTLSReply) {
            return new SmtpSTARTTLSCommand();
        } else {
            return new SmtpUnknownCommand();
        }
    }

    public static SmtpCommand getCommandTypeFromVerb(String verb) {
        switch (verb) {
            case "EHLO":
                return new SmtpEHLOCommand();
            case "HELO":
                return new SmtpHELOCommand();
            case "NOOP":
                return new SmtpNOOPCommand();
            case "AUTH":
                return new SmtpAUTHCommand();
            case "EXPN":
                return new SmtpEXPNCommand();
            case "VRFY":
                return new SmtpVRFYCommand();
            case "MAIL":
                return new SmtpMAILCommand();
            case "RSET":
                return new SmtpRSETCommand();
            case "DATA":
                return new SmtpDATACommand();
            case "RCPT":
                return new SmtpRCPTCommand();
            case "HELP":
                return new SmtpHELPCommand();
            case "QUIT":
                return new SmtpQUITCommand();
            case "STARTTLS":
                return new SmtpSTARTTLSCommand();
            default:
                return new SmtpUnknownCommand();
        }
    }

}
