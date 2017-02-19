ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'DELL/EMC',
                    'version': '1.0'}



import subprocess
import sys
import logging
from nas_acl_table import *
from nas_acl_entry import *
from nas_acl_counter import *
from nas_acl_stats import *
import cps
import cps_utils
from ansible.module_utils.basic import *

passed = []
total = []

def to_lines(stdout):
    for item in stdout:
        if isinstance(item, basestring):
            item = str(item).split('\n')
        yield item

def parse_show_version(output):

    """Parses the given show version output and returns a version dictionary"""

    version = {}

    for line in output.split('\n'):
        try:
            (key, value) = line.split('=')
            version[key] = value
        except (IndexError, ValueError):
            pass
    return version

def acl_ut_table_create(prio=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        tid = nas_acl.create_table(stage='INGRESS', prio=prio,
                                   allow_filters=[
                                   'SRC_IP', 'SRC_MAC', 'DST_IP', 'IP_TYPE',
                                   'TCP_FLAGS', 'DSCP', 'ECN', 'IPV6_FLOW_LABEL',
                                   'IN_PORTS', 'IN_PORT'])
    except RuntimeError as r:
        print (sys._getframe().f_code.co_name + ": Error creating Table")
        return None

    print (sys._getframe().f_code.co_name + " - Created Table " + str(tid))
    passed.append(sys._getframe().f_code.co_name)
    return tid

#def acl_ut_counter_get(table_id=None, counter_id=None):
#    global total, passed
#    total.append(sys._getframe().f_code.co_name)
#    try:
#        print '#### Counter Show ####'
#        nas_acl.print_counter(table_id, counter_id)
#        passed.append(sys._getframe().f_code.co_name)
#    except RuntimeError:
#        print (sys._getframe().f_code.co_name + " - Error in Get")
#
def create_table(stage, prio, allow_filters, switch_id=0):
    t = TableCPSObj(stage=stage, priority=prio, switch_id=switch_id)

    for f in allow_filters:
        t.add_allow_filter(f)

    upd = ('create', t.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Table create failed")

    t = TableCPSObj(cps_data=r[0])
    table_id = t.extract_id()
    print "Created Table " + str(table_id)
    return table_id

def main():
    table_id = None
    entry_id = None
    #module = AnsibleModule(argument_spec={})
    #module = AnsibleModule(
    #             argument_spec=dict(
    #                 detailed_version=dict(required=False,
    #                                       default=False,
    #                                       type='bool'),
    #                 ),
    #             supports_check_mode=True
    #)
    module = AnsibleModule(argument_spec={})
    detailed_version = module.params['detailed_version']
    if not detailed_version:
        try:
            result = dict(changed=False)
            result['stdout'] = list()
            result['warnings'] = "This is my warnings"
            result['stdout'].append("Line one of Some thing")

            allow_filters=[
            'SRC_IP', 'SRC_MAC', 'DST_IP', 'IP_TYPE',
            'TCP_FLAGS', 'DSCP', 'ECN', 'IPV6_FLOW_LABEL',
            'IN_PORTS', 'IN_PORT']

            output = create_table('INGRESS', 50, allow_filters, switch_id=0)
            result['stdout'].append(output)
            result['stdout_lines'] = list(to_lines(result['stdout']))
            module.exit_json(**result)

            #output = subprocess.check_output(['/opt/dell/os10/bin/os10-show-version'])
            #response = {"tableid": result}
            #version = parse_show_version(output)
            ##module.exit_json(changed=False, meta=output)
            #module.exit_json(changed=False, meta=response)
            ##module.exit_json(changed=False, ansible_facts=version)
        except subprocess.CalledProcessError as error:
            module.fail_json(msg='Detailed option not supported yet')
    else:
        module.fail_json(msg='Detailed option not supported yet')

    #response = {"hello": "world"}



if __name__ == '__main__':
    main()
