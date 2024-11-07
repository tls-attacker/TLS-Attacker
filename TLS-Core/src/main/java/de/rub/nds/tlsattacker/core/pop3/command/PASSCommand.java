package de.rub.nds.tlsattacker.core.pop3.command;

public class PASSCommand extends Pop3Command {
    private final String password;

    public PASSCommand(String password) {
        super("PASS", password);
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
