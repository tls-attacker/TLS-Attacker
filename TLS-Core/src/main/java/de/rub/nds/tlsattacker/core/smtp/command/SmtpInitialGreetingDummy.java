package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;

import java.io.InputStream;

/**
 * This class represents the initial greeting of the SMTP server when a connection is established.
 * Its only use is to be able to distinguish between the initial greeting and truly unknown commands when `receiving` in SmtpLayer.
 * It should never be included in a Workflow.

 */
public class SmtpInitialGreetingDummy extends SmtpCommand {
    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(SmtpContext context, InputStream stream) {
        throw new UnsupportedOperationException("This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpCommandPreparator<? extends SmtpCommand> getPreparator(SmtpContext context) {
        throw new UnsupportedOperationException("This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpCommandSerializer<? extends SmtpCommand> getSerializer(SmtpContext context) {
        throw new UnsupportedOperationException("This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        throw new UnsupportedOperationException("This is a dummy class that should not be included in a Workflow.");
    }
}
