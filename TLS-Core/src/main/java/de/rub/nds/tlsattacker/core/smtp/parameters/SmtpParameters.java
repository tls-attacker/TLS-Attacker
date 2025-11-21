/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parameters;

import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;

public class SmtpParameters {
    private SmtpServiceExtension extension;
    private String parameters;

    public SmtpParameters(SmtpServiceExtension extension, String parameters) {
        this.extension = extension;
        this.parameters = parameters;
    }

    public SmtpServiceExtension getExtension() {
        return extension;
    }

    public String getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    public void setExtension(SmtpServiceExtension extension) {
        this.extension = extension;
    }

    public String serialize() {
        return extension.serialize() + "=" + parameters;
    }
}
