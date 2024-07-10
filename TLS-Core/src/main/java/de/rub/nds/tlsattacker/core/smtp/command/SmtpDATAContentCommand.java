/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.DATAContentCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.DATAContentParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;
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

    public void setLines(List<String> lines) {
        this.lines = lines;
    }

    @Override
    public DATAContentParser getParser(SmtpContext context, InputStream stream) {
        return new DATAContentParser(stream);
    }

    public DATAContentCommandHandler getHandler(SmtpContext context) {
        return new DATAContentCommandHandler(context);
    }
}
