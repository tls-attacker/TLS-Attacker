package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.LISTReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class Pop3LISTReply extends Pop3Reply {
    private List<String> messageNumbers = new ArrayList<>();
    private List<String> messageOctets = new ArrayList<>();

    public Pop3LISTReply() {super();}

    @Override
    public LISTReplyParser getParser(Pop3Context context, InputStream stream) {
        return new LISTReplyParser(stream);
    }

    public void setMessageNumbers(List<String> messageNumbers) {
        this.messageNumbers = messageNumbers;
    }

    public List<String> getMessageNumbers() {
        return messageNumbers;
    }

    public void addMessageNumber(String messageNumber) {
        this.messageNumbers.add(messageNumber);
    }

    public void addMessageOctet(String messageOctet) {
        this.messageOctets.add(messageOctet);
    }

    public void setMessageOctets(List<String> messageOctets) {
        this.messageOctets = messageOctets;
    }
    public List<String> getMessageOctets() {
        return messageOctets;
    }

    @Override
    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();
        sb.append(this.statusIndicator);
        sb.append(CRLF);
        for (int i = 0; i < messageNumbers.size(); i++) {
            sb.append(messageNumbers.get(i));
            sb.append(SP);
            sb.append(messageOctets.get(i));
            sb.append(CRLF);
        }
        if (messageOctets.size() > 1) {
            sb.append(".");
            sb.append(CRLF);
        }

        return sb.toString();
    }
}
