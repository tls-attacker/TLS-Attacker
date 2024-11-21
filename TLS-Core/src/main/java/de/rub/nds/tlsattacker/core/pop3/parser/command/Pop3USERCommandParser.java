package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.command.USERCommand;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class Pop3USERCommandParser extends Pop3MessageParser<USERCommand> {
    private static final Logger LOGGER = LogManager.getLogger();

    public Pop3USERCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(USERCommand userCommand) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ");
        String keyword = lineContents[0];

        userCommand.setKeyword(keyword);

        if (lineContents.length == 1) {
            LOGGER.warn("Expected username but only got keyword. Proceeding with username = null.");

            return;
        }

        String arguments = line.substring(keyword.length() + 1);
        userCommand.setArguments(arguments);
        userCommand.setUsername(lineContents[1]);

        if (lineContents.length > 2) {
            LOGGER.warn("Expected only keyword and username but got: " + arguments + ". '" + lineContents[1] + "' will be saved as username.");
        }
    }
}
