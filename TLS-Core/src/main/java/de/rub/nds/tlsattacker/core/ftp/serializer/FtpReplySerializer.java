/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.serializer;

import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import java.nio.charset.StandardCharsets;

/**
 * Serializes FTP replies. The responsibility for the reply formatting lies with the serialize()
 * method of the reply class.
 *
 * @param <ReplyT> The FTP reply to serialize.
 */
public class FtpReplySerializer<ReplyT extends FtpReply> extends FtpMessageSerializer<ReplyT> {

    private final FtpReply reply;

    public FtpReplySerializer(ReplyT reply, FtpContext context) {
        super(reply, context);
        this.reply = reply;
    }

    @Override
    protected byte[] serializeBytes() {
        byte[] output = this.reply.serialize().getBytes(StandardCharsets.US_ASCII);
        appendBytes(output);
        return getAlreadySerialized();
    }
}
