/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpRCPTCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpRCPTCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpRCPTCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents an SMTP RCPT command, which is used to identify an individual recipient of
 * the mail data; multiple recipients are specified by multiple uses of this command. The argument
 * clause contains a forward-path and may contain optional parameters. Example: <br>
 *
 * <pre>
 * C: RCPT TO:&lt;recipient@example.com&gt; <br>
 * S: 250 2.1.5 Ok
 * </pre>
 */
@XmlRootElement
public class SmtpRCPTCommand extends SmtpCommand {
    private String recipient;
    private List<String> rcptParameters = new ArrayList<>();

    public SmtpRCPTCommand() {
        super(SmtpCommandType.RCPT);
    }

    public SmtpRCPTCommand(String recipient) {
        this();
        this.recipient = recipient;
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getRecipient() {
        return recipient;
    }

    @Override
    public SmtpRCPTCommandParser getParser(Context context, InputStream stream) {
        return new SmtpRCPTCommandParser(stream);
    }

    @Override
    public SmtpRCPTCommandPreparator getPreparator(Context context) {
        return new SmtpRCPTCommandPreparator(context.getSmtpContext(), this);
    }

    @Override
    public SmtpRCPTCommandHandler getHandler(Context context) {
        return new SmtpRCPTCommandHandler(context.getSmtpContext());
    }

    public List<String> getRcptParameters() {
        return rcptParameters;
    }

    public void setRcptParameters(List<String> rcptParameters) {
        this.rcptParameters = rcptParameters;
    }
}
