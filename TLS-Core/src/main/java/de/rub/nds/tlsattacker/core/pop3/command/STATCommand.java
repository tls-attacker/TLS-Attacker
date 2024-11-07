package de.rub.nds.tlsattacker.core.pop3.command;

// TODO: decide whether to change naming convention, e.g. Pop3StatCommand is less readable imo

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
}
