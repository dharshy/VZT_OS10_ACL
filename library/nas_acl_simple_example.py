#!/usr/bin/python

import nas_acl

#
# ACL Table to hold the ACL Entries.
#
def main():
  
  tid = nas_acl.create_table(stage='EGRESS',
                             prio=99,
                             allow_filters=['SRC_IP', 'DST_IP',
                                            'IN_PORT', 'OUT_PORT', 'L4_SRC_PORT', 'L4_DST_PORT'])
  
  #
  # ACL Entry to drop all packets received from DST_IP on L4_DST_PORT 
  #
  # ACL counter to count number of dropped packets
  #counter_mac = nas_acl.create_counter(table_id=tid, types=['PACKET'])
  # CPS Create the ACL entry
  eid_tcp = nas_acl.create_entry(table_id=tid,
                                 prio=512,
                                 filter_map={'SRC_IP': {'addr': '23.0.0.1', 'mask': '255.0.0.0'},
                                             'L4_SRC_PORT': 443,},
                                 action_map={'PACKET_ACTION': 'DROP'})
  """
  eid_ip = nas_acl.create_entry(table_id=tid,
                                prio=511,
                                filter_map={'DST_IP': '23.0.0.1',
                                            'DSCP': {'data':0x08, 'mask':0x38}},
                                action_map={'SET_TC': 4,
                                            'SET_COUNTER': counter_ip})
  """
  # Print both entries in ACL table
  nas_acl.print_entry(tid)
  #return tid,eid_mac

  #raw_input("Press Enter to clean up the ACL entries and table ...")

  # Print the ACL stats object
  #nas_acl.print_stats(tid, counter_ip)
  nas_acl.print_stats(tid)

  # Clean up
  #nas_acl.delete_entry(tid, eid_ip)
  #nas_acl.delete_entry(tid, eid_tcp)
  #nas_acl.delete_counter(tid, counter_ip)
  #nas_acl.delete_counter(tid, counter_mac)
  #nas_acl.delete_table(tid)
  #print "Clean up Successful"

if __name__ == "__main__":
     
  #table_id, entry_id = main()
  main()



