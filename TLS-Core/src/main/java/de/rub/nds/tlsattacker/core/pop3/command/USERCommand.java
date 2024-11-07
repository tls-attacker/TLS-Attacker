package de.rub.nds.tlsattacker.core.pop3.command;

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
}
