/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

/**
 * Generic SMTP Service Extension. Extensions are specified by the IANA, but for our purposes we
 * only store keywords and parameters.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class SmtpServiceExtension {

    private String ehloKeyword;
    private String parameters = null;

    /** Default constructor required for JAXB unmarshalling of workflow traces. */
    private SmtpServiceExtension() {}

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

    public String getParameters() {
        return parameters;
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder();

        sb.append(this.ehloKeyword);
        if (this.parameters != null) {
            sb.append(' ');
            sb.append(parameters);
        }

        return sb.toString();
    }
}
