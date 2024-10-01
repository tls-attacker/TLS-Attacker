/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.serializer;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

/*
   This class serializes SMTP replies.
   A reply is serialized in the format "REPLY_CODE<SP>[RESPONSE CONTENT]<CRLF>".
   Where <SP> is a space character and <CRLF> is a carriage return followed by a line feed.
   A reply can be multiline of the format "REPLY_CODE-[CONTENT1]<CRLF>...<CRLF>REPLYCODE [CONTENTn]<CRLF>.
*/
public class SmtpReplySerializer<ReplyT extends SmtpReply> extends SmtpMessageSerializer<ReplyT> {

    private final SmtpReply reply;

    public SmtpReplySerializer(SmtpContext context, ReplyT smtpReply) {
        super(smtpReply, context);
        this.reply = smtpReply;
    }

    @Override
    protected byte[] serializeBytes() {
        byte[] output = this.reply.toString().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
