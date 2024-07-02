package de.rub.nds.tlsattacker.core.smtp.command;


/**
 * This class represents an SMTP MAIL command, which is used to initiate a mail transaction.
 * The argument clause contains a reverse-path and may contain optional parameter.
 * The reverse path represents the senders mailbox.
 */
public class SmtpMAILCommand extends SmtpCommand {

    private static final String COMMAND = "MAIL";

    private String reversePath;

    private String MailParameters;


    public SmtpMAILCommand() {
        super(COMMAND,null);
    }

    public SmtpMAILCommand(String parameters) {
        super(COMMAND, parameters);
        String[] pars = parameters.split(" ");
        this.reversePath = pars[0];
        this.MailParameters = pars[1];

    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }


    public String getReversePath() { return reversePath;}

    public void setReversePath(String reversePath) {this.reversePath = reversePath;}
    
    public String getMailParameters() { return MailParameters;}

    public void setMailParameters(String mailParameters) {
        MailParameters = mailParameters;
    }
}
