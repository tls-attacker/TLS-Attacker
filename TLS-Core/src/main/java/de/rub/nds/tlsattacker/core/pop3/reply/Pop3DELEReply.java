/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3DELEReplyHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3GenericReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class Pop3DELEReply extends Pop3Reply {

    public Pop3DELEReply() {
        super(Pop3CommandType.DELE);
    }

    @Override
    public Pop3GenericReplyParser<Pop3DELEReply> getParser(Context context, InputStream stream) {
        return new Pop3GenericReplyParser<>(stream);
    }

    @Override
    public Pop3DELEReplyHandler getHandler(Context context) {
        return new Pop3DELEReplyHandler(context.getPop3Context());
    }
}
