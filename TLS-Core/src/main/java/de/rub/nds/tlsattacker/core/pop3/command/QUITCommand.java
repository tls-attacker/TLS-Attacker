package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;

import java.io.InputStream;

public class QUITCommand extends Pop3Command {
    public QUITCommand() {
        super("QUIT", null);
    }

    @Override
    public Pop3CommandParser<QUITCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }
}
