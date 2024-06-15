package de.rub.nds.tlsattacker.core.smtp.command;

public class SmtpMAILCommand extends SmtpCommand {

    private static final String COMMAND = "MAIL";

    private String reversePath;

    public SmtpMAILCommand() {
        super(COMMAND,null);
    }

    public SmtpMAILCommand(String reversePath) {
        super(COMMAND, null);
        clearBuffers();
        insertReversePath(reversePath);

    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }


    public String getReversePath() { return reversePath;}

    public void setReversePath(String reversePath) {this.reversePath = reversePath;}
}
