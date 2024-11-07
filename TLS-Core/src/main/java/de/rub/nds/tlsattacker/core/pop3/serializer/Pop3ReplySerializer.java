/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.serializer;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;

public class Pop3ReplySerializer<ReplyT extends Pop3Reply> extends Pop3MessageSerializer<ReplyT> {

    private final Pop3Reply reply;

    public Pop3ReplySerializer(ReplyT reply, Pop3Context context) {
        super(reply, context);
        this.reply = reply;
    }

    @Override
    protected byte[] serializeBytes() {

        byte[] output = this.reply.serialize().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
