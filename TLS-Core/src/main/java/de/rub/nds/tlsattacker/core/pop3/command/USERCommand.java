package de.rub.nds.tlsattacker.core.pop3.command;

public class USERCommand extends Pop3Command {
    private final String username;

    public USERCommand(String username) {
        super("USER", username);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
