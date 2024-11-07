package de.rub.nds.tlsattacker.core.pop3.command;

/**
 * With no parameters, this command lists all messages with corresponding message information.
 * With a message number specified, it only lists the information of one message.
 */
public class LISTCommand extends Pop3Command {

    private static final String CMD = "LIST";

    private int messageNumber; // optional, TODO: decide whether having this as a string is more convenient

    public LISTCommand() {
        super(CMD, null);
    }

    public LISTCommand(int messageNumber) {
        super(CMD, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public int getMessageNumber() {
        return messageNumber;
    }
}
