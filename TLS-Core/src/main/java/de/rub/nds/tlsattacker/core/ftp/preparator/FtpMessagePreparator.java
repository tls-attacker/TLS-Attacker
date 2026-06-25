/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.preparator;

import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * The specific preparators, i.e. the children of this class, check whether necessary values are
 * set. If not, default values will be loaded from the config.
 *
 * @param <MessageT> Any FTP command or reply.
 */
public class FtpMessagePreparator<MessageT extends FtpMessage> extends Preparator<MessageT> {

    protected final FtpContext context;

    public FtpMessagePreparator(Chooser chooser, MessageT message) {
        super(chooser, message);
        this.context = chooser.getContext().getFtpContext();
    }

    @Override
    public void prepare() {}

    public FtpContext getContext() {
        return context;
    }
}
