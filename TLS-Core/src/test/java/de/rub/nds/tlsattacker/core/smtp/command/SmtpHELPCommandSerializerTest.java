package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SmtpHELPCommandSerializerTest {
    @Test
    public void testSerialization() {
        //given an SmtpHELPCommand see if getSerializer leads to something worthwhile
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand("seal.upb.de");
        SmtpCommandPreparator<SmtpHELPCommand> preparator = HELPCommand.getPreparator(context);
        //TODO: this is me misusing generics but I don't know how to fix it
        SmtpCommandSerializer<?> serializer = HELPCommand.getSerializer(context);
        preparator.prepare();
        byte[] out = serializer.serialize();
        Assertions.assertEquals("HELP seal.upb.de\r\n", new String(out));

    }
}