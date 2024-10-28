package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import java.io.InputStream;

/**
 * Parses Pop3Command from an InputStream. Simple parser to set command keyword and arguments.
 * Subclasses need to implement specific parsing for specific commands
 *
 * @param <CommandT> command to be parsed
 */

public class Pop3CommandParser<CommandT extends Pop3Command> extends Pop3MessageParser<CommandT> {

    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data from
     */
    public Pop3CommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Does general parsing of setting the keyword and arguments
     * specific parsing of arguments is implemented by specific command parser
     * @param pop3Command Command that is parsed
     */
    public void parse(CommandT pop3Command) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ", 2);
        pop3Command.setKeyword(lineContents[0]);
        if (lineContents.length == 2) {
            pop3Command.setArguments(lineContents[1]);
        }
        parseArguments(pop3Command, pop3Command.getArguments());
    }

    /**
     * Parse arguments of Pop3Command. Subclass needs to implement this method.
     * For invalid arguments a ParserException should be thrown
     * @param command pop3Command to parse arguments for
     * @param arguments arguments string containing everything after first space
     */
    public void parseArguments(CommandT command, String arguments) {}
}
