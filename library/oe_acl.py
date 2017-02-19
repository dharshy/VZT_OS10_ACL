#!/usr/bin/python

import nas_acl
import argparse
import sys
import cps

_valid_ops=['show-table','find-table','create-table','delete-table',\
  'show-entry','find-entry','create-entry','delete-entry']
_valid_match_fields=['SRC_IP','DST_IP','IN_PORT','OUT_PORT','L4_SRC_PORT','L4_DST_PORT']
_valid_stages=['EGRESS','INGRESS']
_entry_actions=['DROP']

parser = argparse.ArgumentParser(description='This tool will perform ACL \
    related command line operations')
parser.add_argument('-op',choices=_valid_ops,help='Show all acl entries \
    in the table',action='store',required=True)
parser.add_argument('-table-priority',action='store',type=int,help='The ACL table priority',required=False)
parser.add_argument('-table-match',choices=_valid_match_fields,action='append',help='These are the possible match fields',required=False)
parser.add_argument('-table-stage',help='This is the stage at which to install the ACL',choices=_valid_stages,required=False)

parser.add_argument('-entry-sipv4',help="Source IPv4 address and mask (eg. 1.1.1.1/255.255.255.0)",required=False)
parser.add_argument('-entry-sport',required=False,type=int)
parser.add_argument('-entry-action',choices=_entry_actions,help='The action to take',required=False)

parser.add_argument('-entry-prio',help='The ACL entry priority',type=int,required=False)

parser.add_argument('-table-id',help='The table ID',required=False)
parser.add_argument('-entry-id',help='The entry ID',required=False)

parser.add_argument('-d',help='Enable debug operations',action='store_true',required=False)
_args = vars(parser.parse_args())

def __show_table():
  print "ACL Tables display..."
  print "Key is the instance ID of the acl table"
  nas_acl.print_table()

def __find_table():
  _table = nas_acl.find_table(priority=_args['table_priority'],matchfields=_args['table_match'],\
        table_stage=_args['table_stage'])
  return _table

def __find_table_show():
  _table = __find_table()
  if _table==None:
    print 'Not found'
    sys.exit(1)
  _table.print_obj()

def __create_table():
  if _args['table_stage']==None or _args['table_priority']==None or _args['table_match']==None:
    print('Missing manditory attributes to create table')
    sys.exit(1)
  _table_id = nas_acl.create_table(stage=_args['table_stage'],prio=_args['table_priority'],\
      allow_filters=_args['table_match'],only_if_not_exist=True)

  _table = nas_acl.TableCPSObj (table_id=_table_id)
  out = []
  if cps.get ([_table.data()], out) == True:
      for t_cps in out:
        t = nas_acl.TableCPSObj (cps_data = t_cps)
        _table = t

  return _table

def __create_table_show():
  _table = __create_table()
  if _table!=None:
    _table.print_obj()
  else:
    print('Error creating table')
  sys.exit(0)

def __delete_table():
  _table = nas_acl.find_table(priority=_args['table_priority'],matchfields=_args['table_match'],\
        table_stage=_args['table_stage'])
  if _table!=None:
    _id = _table.extract_id()
    nas_acl.delete_table(_id)
    print('Table deleted...')
  sys.exit(0)

def __show_entry():
  nas_acl.print_entry()

def __find_entry():
  _table = __find_table()
  if _table==None:
    return None
  _table_id = _table.extract_id()

  _entry = nas_acl.find_entry(table_id=_table_id,priority=_args['entry_prio'],\
    s_ipv4=_args['entry_sipv4'],s_mask4=_args['entry_smask4'],\
    s_port=_args['entry_sport'])

  return _entry

def __find_entry_show():
  _entry = __find_entry()
  if _entry==None:
    print('Entry is not found.')
    sys.exit(1)

  _entry.print_obj()

def __create_entry():
  _entry = __find_entry()
  if _entry!=None:
    print('Exists already')
    return
  _table = __create_table()
  _id = _table.extract_id()
  _prio = _args['entry_prio']
  _filters={}

  if _args['entry_sipv4']!=None:
    _filters['SRC_IP']={ 'addr' : _args['entry_sipv4'],
                        'mask' : _args['entry_smask4']}
  if _args['entry_sport']!=None:
    _filters['L4_SRC_PORT']=_args['entry_sport']

  _actions={}
  if _args['entry_action']!=None:
    _actions={'PACKET_ACTION': _args['entry_action']}

  if len(_filters)==0 or len(_actions)==0:
    print("Incomplete entry parameters")
    sys.exit(1)

  _res = nas_acl.create_entry(_id,_prio,_filters,_actions)
  print _res

def __delete_entry() :
  if _args['table_id']==None or _args['entry_id']==None:
    print('Missing parameters.. please specify both table and entry IDs')
    sys.exit(1)
  nas_acl.delete_entry(_args['table_id'],_args['entry_id'])


__ops={
  'show-table':__show_table,
  'find-table':__find_table_show,
  'create-table':__create_table,
  'delete-table':__delete_table,
  'show-entry':__show_entry,
  'find-entry':__find_entry_show,
  'create-entry':__create_entry,
  'delete-entry':__delete_entry,
}

def main():
  if _args['entry_sipv4']!=None:
    _sep = _args['entry_sipv4'].split('/')
    if len(_sep)!=2:
      print("Missing IPv4 Mask or incomplete address")
      sys.exit(1)
    _args['entry_smask4'] = _sep[1]
    _args['entry_sipv4'] = _sep[0]

  if _args['d']:
    print _args

  _op = _args['op']
  __ops[_op]()
  sys.exit(0)

if __name__ == "__main__":
  main()