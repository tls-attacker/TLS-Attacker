/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.DATAContentParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class DATAContentCommandTest {

    private final String CRLF = "\r\n";
    private final String[] lines = new String[] {"This is some", "multi-line", "data content."};

    @Test
    public void testValidDataContent() {
        String content = lines[0] + CRLF + lines[1] + CRLF + lines[2] + CRLF + "." + CRLF;

        SmtpDATAContentCommand dcc = new SmtpDATAContentCommand();

        DATAContentParser parser =
                new DATAContentParser(
                        new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));

        parser.parse(dcc);
        assertArrayEquals(lines, dcc.getLines().toArray());
    }

    @Test
    public void testMissingEndSequence() {
        String content = lines[0] + CRLF + lines[1] + CRLF + lines[2] + CRLF;

        DATAContentParser parser =
                new DATAContentParser(
                        new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));

        SmtpDATAContentCommand dcc = new SmtpDATAContentCommand();

        assertThrows(RuntimeException.class, () -> parser.parse(dcc));
    }

    @Test
    public void testSerializer() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));

        String content = lines[0] + CRLF + lines[1] + CRLF + lines[2] + CRLF + "." + CRLF;
        SmtpDATAContentCommand dcc = new SmtpDATAContentCommand(lines);

        Preparator preparator = dcc.getPreparator(context);
        Serializer serializer = dcc.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals(content, serializer.getOutputStream().toString());
    }

    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        String content = lines[0] + CRLF + lines[1] + CRLF + lines[2] + CRLF + "." + CRLF;
        SmtpDATAContentCommand dcc = new SmtpDATAContentCommand(content);
        DATAContentParser parser =
                new DATAContentParser(
                        new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        parser.parse(dcc);
        Handler handler = dcc.getHandler(context);
        handler.adjustContext(dcc);
        System.out.println(context.getMailDataBuffer());
        System.out.println(dcc.getLines());
        assertLinesMatch(context.getMailDataBuffer(), dcc.getLines());
    }
}
