package de.rub.nds.tlsattacker.core.smtp.extensions;

public class UnknownEHLOExtension extends SmtpServiceExtension {
    public UnknownEHLOExtension(String ehloKeyword, String parameters) {
        super(ehloKeyword, parameters);
    }
}
