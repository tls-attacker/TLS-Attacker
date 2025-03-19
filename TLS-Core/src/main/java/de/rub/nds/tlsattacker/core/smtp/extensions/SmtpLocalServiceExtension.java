/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

/**
 * In addition, any EHLO keyword value starting with an upper or lower case "X" refers to a local
 * SMTP service extension used exclusively through bilateral agreement. Keywords beginning with "X"
 * MUST NOT be used in a registered service extension. Conversely, keyword values presented in the
 * EHLO response that do not begin with "X" MUST correspond to a Standard, Standards-Track, or
 * IESG-approved Experimental SMTP service extension registered with IANA. A conforming server MUST
 * NOT offer non-"X"-prefixed keyword values that are not described in a registered extension.
 */
public class SmtpLocalServiceExtension extends SmtpServiceExtension {
    public SmtpLocalServiceExtension() {
        this("", "");
    }

    public SmtpLocalServiceExtension(String ehloKeyword, String parameters) {
        super(ehloKeyword);
    }
}
