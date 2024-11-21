package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.PASSReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class Pop3PASSReply extends Pop3Reply{

    public Pop3PASSReply() {super();}

    @Override
    public PASSReplyParser getParser(Pop3Context context, InputStream stream) {
        return new PASSReplyParser(stream);
    }
}
