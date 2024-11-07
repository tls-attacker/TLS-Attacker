package de.rub.nds.tlsattacker.core.pop3.command;

// TODO: decide whether to change naming convention, e.g. Pop3StatCommand is less readable imo

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;

import java.io.InputStream;

/**
 * The POP3 STAT command is used to retrieve two stats regarding the mailbox:
 * <ol>
 *     <li>The number of messages in the mailbox.</li>
 *     <li>The total size taken up by all messages (in octets).</li>
 * </ol>
 * The STAT command does not have any parameters.
 */

public class STATCommand extends Pop3Command {
    public STATCommand() {
        super("STAT", null);
    }

    @Override
    public Pop3CommandParser<STATCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }
}
