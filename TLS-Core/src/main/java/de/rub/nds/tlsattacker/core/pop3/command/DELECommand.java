package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;

import java.io.InputStream;

/**
 * The DELECommand deletes a message with the specified messageNumber.
 */
public class DELECommand extends Pop3Command implements MessageNumber {
    private Integer messageNumber;
    private static final String commandName = "DELE";

    public DELECommand() {
        super(commandName);
    }

    public DELECommand(int messageNumber) {
        super(commandName, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public Integer getMessageNumber() {
        return messageNumber;
    }

    public void setMessageNumber(Integer messageNumber) {
        this.messageNumber = messageNumber;
    }

    @Override
    public Pop3CommandParser<DELECommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public String getCommandName() {
        return commandName;
    }
}
