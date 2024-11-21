package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3PASSCommandParser;

import java.io.InputStream;

public class PASSCommand extends Pop3Command {
    private String password;
    private static final String commandName = "PASS";

    public PASSCommand() {
        super(commandName);
    }

    public PASSCommand(String password) {
        super(commandName, password);
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3PASSCommandParser getParser(Pop3Context context, InputStream stream) {
        return new Pop3PASSCommandParser(stream);
    }
}
