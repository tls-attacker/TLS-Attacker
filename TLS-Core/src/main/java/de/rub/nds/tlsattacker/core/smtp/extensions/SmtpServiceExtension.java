/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

/** Enum of SMTP service extensions as maintained by IANA. */
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(this.ehloKeyword);
        if (this.parameters != null) {
            sb.append(' ');
            sb.append(parameters);
        }

        return sb.toString();
    }
}
