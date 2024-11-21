package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.PASSCommand;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

/**
 * The password provided in the PASS command may contain spaces, so everything past PASS is considered the password.
 */

public class Pop3PASSCommandParser extends Pop3MessageParser<PASSCommand> {
    private static final Logger LOGGER = LogManager.getLogger();

    public Pop3PASSCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PASSCommand passCommand) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ", 2);
        String keyword = lineContents[0];

        passCommand.setKeyword(keyword);

        if (lineContents.length == 2) {
            String password = lineContents[1];
            passCommand.setArguments(password);
            passCommand.setPassword(password);
        }
    }
}
