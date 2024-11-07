package de.rub.nds.tlsattacker.core.pop3.command;

/**
 * The DELECommand deletes a message with the specified messageNumber.
 */
public class DELECommand extends Pop3Command {
    private final int messageNumber;

    public DELECommand(int messageNumber) {
        super("DELE", String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public int getMessageNumber() {
        return messageNumber;
    }
}
