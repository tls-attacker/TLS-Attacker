/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.preparator;

import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class FtpReplyPreparator<ReplyT extends FtpReply> extends FtpMessagePreparator<ReplyT> {

    public FtpReplyPreparator(Chooser chooser, ReplyT message) {
        super(chooser, message);
    }
}
