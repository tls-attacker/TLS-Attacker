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
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpEXPNCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpEXPNCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Represents the EXPN command in SMTP, which queries a mailing list for the members.
 *
 * <pre>
 * C: EXPN staff@upb.de
 * S: 250-Jane Doe &lt;jane.doe@upb.de&gt;
 * S: 250-John Smith &lt;john.smith@upb.de&gt;
 * S: 250-Bob Lee &lt;bob.lee@upb.de&gt;
 * </pre>
 */
@XmlRootElement
public class SmtpEXPNCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "EXPN";
    // email address of a mailing list
    private String mailingList;

    public SmtpEXPNCommand() {
        super(SmtpCommandType.EXPN);
    }

    public SmtpEXPNCommand(String mailingList) {
        this();
        this.mailingList = mailingList;
    }

    public String getMailingList() {
        return mailingList;
    }

    public void setMailingList(String mailingList) {
        this.mailingList = mailingList;
    }

    @Override
    public SmtpEXPNCommandParser getParser(Context context, InputStream stream) {
        return new SmtpEXPNCommandParser(stream);
    }

    @Override
    public SmtpEXPNCommandPreparator getPreparator(Context context) {
        return new SmtpEXPNCommandPreparator(context.getSmtpContext(), this);
    }
}
