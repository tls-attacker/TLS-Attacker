package de.rub.nds.tlsattacker.core.pop3.command;

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
}
