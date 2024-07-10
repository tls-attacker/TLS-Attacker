/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement
public class SmtpDATAContentCommand extends SmtpCommand {
    private List<String> lines;

    public SmtpDATAContentCommand() {
        super(null, null);
    }

    public SmtpDATAContentCommand(String parameters) {
        super(null, parameters);
    }

    public List<String> getLines() {
        return lines;
    }

    public void setLines(List<String> content) {
        this.lines = content;
    }
}
