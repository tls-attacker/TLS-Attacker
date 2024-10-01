package de.rub.nds.tlsattacker.core.smtp.command;

import java.util.List;

public class SmtpAUTHCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "AUTH";

    // depending on the mechanism, there CAN (but don't have to) be multiple base64 strings
    private String saslMechanism;
    private String initialResponse;
    private List<String> base64Strings;
    private String cancelResponse;

    // E.g. "AUTH PLAIN"
    public SmtpAUTHCommand(String saslMechanism) {
        super(COMMAND_NAME, saslMechanism);
        this.saslMechanism = saslMechanism;
    }

    // E.g. "AUTH PLAIN Qts12w=="
    public SmtpAUTHCommand(String saslMechanism, String initialResponse) {
        super(COMMAND_NAME);
        this.saslMechanism = saslMechanism;
        this.initialResponse = initialResponse;
    }

    public SmtpAUTHCommand(String saslMechanism, String initialResponse, List<String> base64Strings) {
        super(COMMAND_NAME);
        this.saslMechanism = saslMechanism;
        this.initialResponse = initialResponse;
        this.base64Strings = base64Strings;
    }

    public SmtpAUTHCommand(String saslMechanism, String initialResponse, List<String> base64Strings, String cancelResponse) {
        super(COMMAND_NAME);
        this.saslMechanism = saslMechanism;
        this.initialResponse = initialResponse;
        this.base64Strings = base64Strings;
        this.cancelResponse = cancelResponse;
    }

    // E.g. "AUTH PLAIN *" to cancel authentication
    public SmtpAUTHCommand(String saslMechanism, String initialResponse, String cancelResponse) {
        super(COMMAND_NAME);
        this.saslMechanism = saslMechanism;
        this.initialResponse = initialResponse;
        this.cancelResponse = cancelResponse;
    }
}
