package de.rub.nds.tlsattacker.core.smtp.extensions;

/**
 * Enum of SMTP service extensions as maintained by IANA.
 */
public abstract class SmtpServiceExtension {

    private final String ehloKeyword;
    private String parameters = null;

    public SmtpServiceExtension(String ehloKeyword, String parameters) {
        this.ehloKeyword = ehloKeyword;
        this.parameters = parameters;
    }
    public SmtpServiceExtension(String ehloKeyword) {
        this.ehloKeyword = ehloKeyword;
    }

    public String getEhloKeyword() {
        return ehloKeyword;
    }

    public boolean isImplemented() {
        return false;
    }

    public String getParameters() {
        return parameters;
    }
}
