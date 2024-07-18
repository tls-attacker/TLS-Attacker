/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

import java.util.List;

public class AUTHExtension extends SmtpServiceExtension {

    private List<String> SASLMechanisms;

    public AUTHExtension(List<String> SASLMechanisms) {
        super("AUTH");
        this.SASLMechanisms = SASLMechanisms;
    }

    public List<String> getSASLMechanisms() {
        return SASLMechanisms;
    }

    public void setSASLMechanisms(List<String> SASLMechanisms) {
        this.SASLMechanisms = SASLMechanisms;
    }
}
