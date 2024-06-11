package de.rub.nds.tlsattacker.core.smtp;

/*
    This class serializes SMTP commands.
    Typically, a command is serialized in the format "COMMAND<SP>[PARAMETERS]<CRLF>".
    Where <SP> is a space character and <CRLF> is a carriage return followed by a line feed.
    When there are no parameters, the command is serialized as "COMMAND<CRLF>".
    This is according to the SMTP protocol as defined in RFC 5321.
 */
public class SmtpCommandSerializer extends SmtpMessageSerializer<SmtpCommand> {

    //modeled after their usage in RFC 5321
    private final static String SP = " ";
    private final static String CRLF = "\r\n";

    private final SmtpCommand command;

    public SmtpCommandSerializer(SmtpCommand smtpCommand) {
        super(smtpCommand);
        this.command = smtpCommand;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder builder = new StringBuilder();
        builder.append(this.command.getVerb());
        if (this.command.getParameters() != null) {
            builder.append(SP);
            builder.append(this.command.getParameters());
        }
        builder.append(CRLF);
        return builder.toString().getBytes();
    }
}
