package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

import java.util.ArrayList;
import java.util.List;

public class EHLOReplyPreparator extends SmtpReplyPreparator<SmtpEHLOReply> {
    public EHLOReplyPreparator(SmtpContext context, SmtpEHLOReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        this.getObject().setReplyCode(this.getObject().getReplyCode());
        List<String> replyLines = new ArrayList<>();
        String introduction = getObject().getDomain();
        if(getObject().getGreeting() != null) {
            introduction += " " + getObject().getGreeting();
        }
        replyLines.add(introduction);
        for(SmtpServiceExtension extension : getObject().getExtensions()) {
            String extensionString = extension.getEhloKeyword();
            if (extension.getParameters() != null) {
                extensionString += " " + extension.getParameters();
            }
            replyLines.add(extensionString);
        }
        this.getObject().setReplyLines(replyLines);
    }
}
