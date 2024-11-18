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
import de.rub.nds.tlsattacker.core.smtp.parser.command.DATAContentParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.DATAContentCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the content associated with the DATA command. This can be any text spanning over several
 * lines and ending with a terminating line containing only one dot: &lt;CRLF&gt;.&lt;/CRLF&gt;.
 */
@XmlRootElement
public class SmtpDATAContentCommand extends SmtpCommand {
    private List<String> lines;

    public SmtpDATAContentCommand() {
        super(null, null);
    }

    public SmtpDATAContentCommand(List<String> content) {
        super(null, null);
        this.lines = content;
    }

    public SmtpDATAContentCommand(String... content) {
        super(null, null);
        this.lines = new ArrayList<>(List.of(content));
    }

    public List<String> getLines() {
        return lines;
    }

    public void setLines(List<String> lines) {
        this.lines = new ArrayList<>(lines);
    }

    @Override
    public DATAContentParser getParser(SmtpContext context, InputStream stream) {
        return new DATAContentParser(stream);
    }

    @Override
    public DATAContentCommandHandler getHandler(SmtpContext context) {
        return new DATAContentCommandHandler(context);
    }

    @Override
    public DATAContentCommandPreparator getPreparator(SmtpContext context) {
        return new DATAContentCommandPreparator(context, this);
    }
}
