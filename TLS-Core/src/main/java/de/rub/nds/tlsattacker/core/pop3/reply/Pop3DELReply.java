package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.DELReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class Pop3DELReply extends Pop3Reply{

    public Pop3DELReply() {super();}


    @Override
    public DELReplyParser getParser(Pop3Context context, InputStream stream) {
        return new DELReplyParser(stream);
    }
}
