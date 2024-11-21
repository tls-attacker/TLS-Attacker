package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3USERCommandParser;

import java.io.InputStream;

public class USERCommand extends Pop3Command {
    private String username;

    private static final String commandName = "USER";

    public USERCommand() {
        super(commandName);
    }

    public USERCommand(String username) {
        super(commandName, username);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3USERCommandParser getParser(Pop3Context context, InputStream stream) {
        return new Pop3USERCommandParser(stream);
    }
}
