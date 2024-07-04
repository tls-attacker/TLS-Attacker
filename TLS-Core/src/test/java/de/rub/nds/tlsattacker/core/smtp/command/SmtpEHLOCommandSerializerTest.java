package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;

class SmtpEHLOCommandSerializerTest {
    @Test
    public void testSerialization() {
        //given an SmtpEHLOCommand see if getSerializer leads to something worthwhile
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehloCommand = new SmtpEHLOCommand("seal.upb.de");
        SmtpCommandPreparator<SmtpEHLOCommand> preparator = ehloCommand.getPreparator(context);
        //TODO: this is me misusing generics but I don't know how to fix it
        SmtpCommandSerializer<?> serializer = ehloCommand.getSerializer(context);
        preparator.prepare();
        byte[] out = serializer.serialize();
        Assertions.assertEquals("EHLO seal.upb.de\r\n", new String(out));

    }
}