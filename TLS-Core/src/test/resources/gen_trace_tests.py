"""Create test vectors for workflow trace input/output tests

This script provides a starting point to generate a more complete
set of test vectors for the workflow trace input/output tests.
A test vector file used by the tests has the following contents:

  Optional test description of the test, can be multiple lines.
  The number sign is treated as a delimiter for different sections.
  It can be followed by an arbitrary comment, but must stay in a
  single line. There are at least two sections in each test vector:

  # 1. Followed by the first delimiter is the config to use
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <config>
  </config>

  # 2. Then comes the workflow trace to use
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <workflowTrace>
  </workflowTrace>

  # Positive tests have two extra sections: The expected normalized trace
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <workflowTrace>
      <OutboundConnection>
          <alias>defaultConnection</alias>
          <port>443</port>
          <hostname>localhost</hostname>
          <timeout>1000</timeout>
          <transportHandlerType>TCP</transportHandlerType>
      </OutboundConnection>
  </workflowTrace>

  # And the expected output trace after default filter application
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <workflowTrace/>

Run this module in standalone mode to see an example of how to generate
a test vector.
"""


from textwrap import indent
from copy import deepcopy


def ind(s):
    return indent(str(s), '    ')


class Connection:
    properties = ['alias', 'port', 'hostname', 'timeout', 'transportHandlerType']
    standalone = False
    con_type = 'OutboundConnection'

    def __init__(self, con_type):
        self.con_type = con_type

    def __str__(self):
        xml = ''
        xml_end = ''
        if self.standalone:
            xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        if hasattr(self, 'name'):
            xml += '<' + self.name + '>\n'
            xml_end = '</' + self.name + '>\n'
        else:
            xml += '<%(t)s>\n' % {'t': self.con_type}
            xml_end = '</%(t)s>\n' % {'t': self.con_type}
        for prop in self.properties:
            if hasattr(self, prop):
                xml += '    <%(p)s>%(v)s</%(p)s>\n' % {'p': prop, 'v': getattr(self, prop)}
        xml = xml + xml_end
        return xml


class Config:
    def __str__(self):
        xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        xml += '<config>\n'
        xml_end = '</config>\n'
        if hasattr(self, 'defaultRunningMode'):
            e = '<defaultRunningMode>%s</defaultRunningMode>\n' % self.defaultRunningMode
            xml += ind(e)
        if hasattr(self, 'defaultClientConnection'):
            xml += ind(self.defaultClientConnection)
        if hasattr(self, 'defaultServerConnection'):
            xml += ind(self.defaultServerConnection)
        xml = xml + xml_end
        return xml


class WorkflowTrace:
    connections = []
    actions = []

    def __str__(self):
        xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        xml += '<workflowTrace>\n'
        xml_end = '</workflowTrace>\n'
        inner_xml = ''
        for con in self.connections:
            xml += ind(con)
        for action in self.actions:
            xml += ind(action)
        xml += xml_end
        return xml


class Action:
    action_type = 'SendAction'
    add_empty_records = False

    def __str__(self):
        xml = '<' + self.action_type + '>\n'
        if hasattr(self, 'alias'):
            xml += '    <connectionAlias>%(a)s</connectionAlias>\n' % {'a': self.alias}
        xml += '    <messages>\n'
        xml += '        <ClientHello/>\n'
        xml += '    </messages>\n'
        if self.add_empty_records:
            xml += '    <records/>\n'
        xml += '</' + self.action_type + '>\n'
        return xml


class PositiveTestVector:
    """Test a valid workflow trace input"""

    def __init__(self, config, trace,
                 expected_normalized, expected_filtered, comment=None):
        self.config = config
        self.trace = trace
        self.normalized = expected_normalized
        self.filtered = expected_filtered
        self.comment = comment

    def __str__(self):
        delim = '\n#'
        s = ''
        if self.comment:
            s += self.comment + " \n"
        s += delim + " Given this config: \n"
        s += str(self.config)
        s += delim + " And this input trace\n"
        s += str(self.trace)
        s += delim + " We expect this normalized trace\n"
        s += str(self.normalized)
        s += delim + " And this after default filter application:\n"
        s += str(self.filtered)
        return s

    def to_file(self, filename):
        with open(filename, 'w+') as f:
            f.write(self.__str__());


if __name__ == '__main__':

    def_i_con = Connection('InboundConnection')
    def_i_con.alias = "defaultConnection"
    def_i_con.port = "443"
    def_i_con.hostname = "localhost"
    def_i_con.timeout = "1000"
    def_i_con.transportHandlerType = "TCP"
    def_o_con = Connection('OutboundConnection')
    def_o_con.alias = "defaultConnection"
    def_o_con.port = "443"
    def_o_con.hostname = "localhost"
    def_o_con.timeout = "1000"
    def_o_con.transportHandlerType = "TCP"
    send_action = Action()
    recv_action = Action()
    recv_action.action_type = "ReceiveAction"

    config = Config()
    config.defaultRunningMode = "CLIENT"
    def_c_con = deepcopy(def_o_con)
    def_c_con.name = "defaultClientConnection"
    def_s_con = deepcopy(def_i_con)
    def_s_con.name = "defaultServerConnection"
    config.defaultClientConnection = def_c_con
    config.defaultServerConnection = def_s_con

    trace = WorkflowTrace()
    trace.actions = [send_action, ]

    expected_normalized = WorkflowTrace()
    expected_normalized.connections = [def_o_con, ]
    expected_normalized.actions = [deepcopy(send_action), ]
    for a in expected_normalized.actions:
        a.alias = def_o_con.alias
        a.add_empty_records = True

    expected_filtered = WorkflowTrace()
    expected_filtered.actions = [send_action, ]

    tv = PositiveTestVector(config, trace, expected_normalized, expected_filtered,
                            "This is an extra comment for the test vector")
    print(tv)
    #tv.to_file("gen.xml")