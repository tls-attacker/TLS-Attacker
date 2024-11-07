package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;

import java.io.InputStream;

/**
 * The RETRCommand retrieves the message with the specified messageNumber.
 */
public class RETRCommand extends Pop3Command implements MessageNumber {

    private int messageNumber;
    private static final String commandName = "RETR";

    public RETRCommand() {
        super(commandName);
    }

    public RETRCommand(int messageNumber) {
        super(commandName, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public int getMessageNumber() {
        return messageNumber;
    }

    public void setMessageNumber(int messageNumber) {
        this.messageNumber = messageNumber;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3CommandParser<RETRCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }
}
