package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CustomCommandTest {
    @Test
    public void testSerializeCustom() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpCommand custom = new SmtpCommand("WOW", "such command");

        Preparator<?> preparator = custom.getPreparator(context);
        Serializer<?> serializer = custom.getSerializer(context);
        preparator.prepare();
        serializer.serialize();

        assertEquals("WOW such command\r\n", serializer.getOutputStream().toString());
    }

}
