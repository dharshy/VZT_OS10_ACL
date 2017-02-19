
from nas_acl_table import *
from nas_acl_entry import *
from nas_acl_counter import *
from nas_acl_stats import *
import cps
import cps_utils

def find_table(table_id=None,priority=None,matchfields=None,table_stage=None):
    t = TableCPSObj(table_id=table_id)
    r = []
    if not cps.get([t.data()], r):
        print 'CPS Get failed for ACL Table'
    for t_cps in r:
        _valid = True
        t = TableCPSObj(cps_data=t_cps)
        if priority!=None:
           try:
                _val = t.extract('priority')
                if _val!=priority:
                    continue
           except:
                continue

        if matchfields!=None:
            _val = t.extract('allowed-match-fields')
            for i in matchfields:
                if i in _val: continue
                _valid=False
                break
        if not _valid:
            continue

        if table_stage!=None:
            _val = t.extract('stage')
            if _val!=table_stage:
                continue
        return t
    return None

def find_entry(table_id=None, entry_id=None,priority=None,
    s_ipv4=None,s_mask4=None,s_port=None):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)
    r = []
    if not cps.get([e.data()], r):
        print 'CPS Get failed for ACL Entry' + str(entry_id)
        return
    for e_cps in r:
        e = EntryCPSObj(cps_data=e_cps)
        if priority!=None:
            _prio = e.extract('priority')
            if _prio != priority:
                continue
        if s_ipv4!=None:
            try:
                _val = e.extract('match/SRC_IP_VALUE/addr')
                if _val==None or _val!=s_ipv4:
                    continue
            except:
                continue
        if s_mask4!=None:
            try:
                _val = e.extract('match/SRC_IP_VALUE/addr')
                if _val==None or _val!=s_ipv4:
                    continue
            except:
                continue
        if s_port!=None:
            try:
                _val = e.extract('match/L4_SRC_PORT_VALUE/data')
                if _val==None or str(_val)!=str(s_port):
                    continue
            except:
                continue
        return e
    return None

def create_table(stage, prio, allow_filters, switch_id=0, only_if_not_exist=False):
    if only_if_not_exist:
        _table = find_table(priority=prio,matchfields=allow_filters,\
                table_stage=stage)
        if _table!=None:
            return _table.extract_id()

    t = TableCPSObj(stage=stage, priority=prio, switch_id=switch_id)

    for f in allow_filters:
        t.add_allow_filter(f)

    upd = ('create', t.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Table create failed")

    t = TableCPSObj(cps_data=r[0])
    table_id = t.extract_id()
    return table_id


def create_entry(table_id, prio, filter_map, action_map, switch_id=0):

    e = EntryCPSObj(table_id=table_id, priority=prio, switch_id=switch_id)

    for ftype, fval in filter_map.items():
        e.add_match_filter(filter_type=ftype, filter_val=fval)

    for atype, aval in action_map.items():
        e.add_action(action_type=atype, action_val=aval)

    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry create failed")

    e = EntryCPSObj(cps_data=r[0])
    entry_id = e.extract_id()
    print "Created Entry " + str(entry_id)
    return entry_id


def create_counter(table_id, types=['BYTE'], switch_id=0):
    c = CounterCPSObj(table_id=table_id, types=types, switch_id=switch_id)
    upd = ('create', c.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Counter create failed")

    c = CounterCPSObj(cps_data=r[0])
    counter_id = c.extract_id()
    print "Created Counter " + str(counter_id)
    return counter_id

# Add another filter to the ACL entry


def append_entry_filter(table_id, entry_id, filter_type, filter_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    e.set_filter_val(filter_val)
    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter append failed")

# Change existing filter value in the ACL entry
def mod_entry_filter(table_id, entry_id, filter_type, filter_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    e.set_filter_val(filter_val)
    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter mod failed")


# Remove a filter from the ACL entry
def remove_entry_filter(table_id, entry_id, filter_type):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter remove failed")


# Add another action to the ACL entry
def append_entry_action(table_id, entry_id, action_type, action_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    e.set_action_val(action_val)
    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action append failed")


# Change existing action value in the ACL entry
def mod_entry_action(table_id, entry_id, action_type, action_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    e.set_action_val(action_val)
    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action mod failed")


# Remove an action from the ACL entry
def remove_entry_action(table_id, entry_id, action_type):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action remove failed")


# Completely overwrite the filter list with another set of filters
def replace_entry_filter_list(table_id, entry_id, filter_map):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    for ftype, fval in filter_map.items():
        e.add_match_filter(filter_type=ftype, filter_val=fval)

    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter-list replace failed")

# Completely overwrite the action list with another set of actions


def replace_entry_action_list(table_id, entry_id, action_map):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    for atype, aval in action_map.items():
        e.add_action(action_type=atype, action_val=aval)

    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()
    if r == False:
        raise RuntimeError("Entry action-list replace failed")

def print_table(table_id=None):
    t = TableCPSObj(table_id=table_id)
    r = []
    if not cps.get([t.data()], r):
        print 'CPS Get failed for ACL Table' + str(table_id)
        return
    for t_cps in r:
        t = TableCPSObj(cps_data=t_cps)
        t.print_obj()


def print_entry(table_id=None, entry_id=None):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)
    r = []
    if not cps.get([e.data()], r):
        print 'CPS Get failed for ACL Entry' + str(entry_id)
        return
    for e_cps in r:
        e = EntryCPSObj(cps_data=e_cps)
        e.print_obj()


def print_counter(table_id=None, counter_id=None):
    c = CounterCPSObj(table_id=table_id, counter_id=counter_id)
    r = []
    if not cps.get([c.data()], r):
        print 'CPS Get failed for ACL Counter' + str(counter_id)
        return
    for c_cps in r:
        c = CounterCPSObj(cps_data=c_cps)
        c.print_obj()


def print_stats(table_id=None, counter_id=None):
    c = StatsCPSObj(table_id=table_id, counter_id=counter_id)
    r = []
    if not cps.get([c.data()], r):
        print 'CPS Get failed for ACL Counter Stats' + str(counter_id)
        return
    for c_cps in r:
        c = StatsCPSObj(cps_data=c_cps)
        c.print_obj()
# Clean up
def delete_entry(table_id, entry_id):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry delete failed")


def delete_counter(table_id, counter_id):
    c = CounterCPSObj(table_id=table_id, counter_id=counter_id)

    upd = ('delete', c.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Counter delete failed")


def delete_table(table_id):
    t = TableCPSObj(table_id=table_id)

    upd = ('delete', t.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Table delete failed")