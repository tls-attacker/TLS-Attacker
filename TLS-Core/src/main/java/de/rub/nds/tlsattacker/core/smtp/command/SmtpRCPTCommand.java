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
import de.rub.nds.tlsattacker.core.smtp.handler.RCPTCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.RCPTCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.RCPTCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents an SMTP RCPT command, which is used to identify an individual recipient of
 * the mail data; multiple recipients are specified by multiple uses of this command. The argument
 * clause contains a forward-path and may contain optional parameters.
 */
@XmlRootElement
public class SmtpRCPTCommand extends SmtpCommand {
    private static final String COMMAND = "RCPT";
    private String recipient;
    //    private List<String> hops = new ArrayList<>();
    private List<String> rcptParameters = new ArrayList<>();

    //    private boolean validRecipient = true;

    public SmtpRCPTCommand() {
        super(COMMAND, null);
    }

    public SmtpRCPTCommand(String recipient) {
        super(COMMAND, null);
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

    //    public List<String> getHops() {
    //        return hops;
    //    }
    //
    //    public void setHops(List<String> hops) {
    //        this.hops = hops;
    //    }

    //    public boolean isValidRecipient() {
    //        return validRecipient;
    //    }
    //
    //    public void setValidRecipient(boolean valid) {
    //        this.validRecipient = valid;
    //    }

    @Override
    public RCPTCommandParser getParser(SmtpContext context, InputStream stream) {
        return new RCPTCommandParser(stream);
    }

    @Override
    public RCPTCommandPreparator getPreparator(SmtpContext context) {
        return new RCPTCommandPreparator(context, this);
    }

    @Override
    public RCPTCommandHandler getHandler(SmtpContext context) {
        return new RCPTCommandHandler(context);
    }

    public List<String> getRcptParameters() {
        return rcptParameters;
    }

    public void setRcptParameters(List<String> rcptParameters) {
        this.rcptParameters = rcptParameters;
    }
}
