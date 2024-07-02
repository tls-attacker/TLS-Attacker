package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class SmtpEHLOReply extends SmtpReply {
    private String domain;
    private String greeting;
    private List<SmtpServiceExtension> extensions;

    public SmtpEHLOReply() {
        super();
        this.extensions = new ArrayList<>();
    }

    @Override
    public EHLOReplyParser getParser(SmtpContext context, InputStream stream) {
        return new EHLOReplyParser(stream);
    }

    public String getGreeting() {
        return greeting;
    }

    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public List<SmtpServiceExtension> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<SmtpServiceExtension> extensions) {
        this.extensions = extensions;
    }
}

