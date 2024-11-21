package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.NOOPReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class Pop3NOOPReply extends Pop3Reply {

    public Pop3NOOPReply() {super();}

    public NOOPReplyParser getParser(Pop3Context context, InputStream stream) {
        return new NOOPReplyParser(stream);
    }
}
