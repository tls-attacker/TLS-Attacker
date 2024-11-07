package de.rub.nds.tlsattacker.core.pop3.command;

/**
 * The RETRCommand retrieves the message with the specified messageNumber.
 */
public class RETRCommand extends Pop3Command {

    private final int messageNumber;

    public RETRCommand(int messageNumber) {
        super("RETR", String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public int getMessageNumber() {
        return messageNumber;
    }
}
