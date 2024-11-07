package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;

import java.io.InputStream;

public class NOOPCommand extends Pop3Command {
    public NOOPCommand() {
        super("NOOP", null);
    }

    @Override
    public Pop3CommandParser<NOOPCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }
}
