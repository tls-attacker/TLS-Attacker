package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCommandParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCredentialsParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AUTHCredentialsCommandTest {
    @Test
    void testParseBasic() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCredentialsCommand authCredentials = new SmtpAUTHCredentialsCommand();
        String stringMessage = "qweqweqwe==\r\n";

        AUTHCredentialsParser parser =
                authCredentials.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(authCredentials);
        assertEquals(authCredentials.getCredentials(), "qweqweqwe==");
    }

}
