package de.rub.nds.tlsattacker.core.https;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.protocol.Parser;

public abstract class HttpsMessageParser<Message extends HttpsMessage> extends Parser<Message> {

    public HttpsMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public final void parse(Message message) {
        parseMessageContent(message);
    }

    protected abstract void parseMessageContent(Message message);
}
