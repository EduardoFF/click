lcm-gen --python --ppath python/ --package-prefix rnp lcmtypes/route_entry_t.lcm lcmtypes/route_table_t.lcm \
  lcmtypes/route_tree_t.lcm lcmtypes/flow_entry_t.lcm lcmtypes/flow_list_t.lcm

lcm-gen --cpp lcmtypes/route_entry_t.lcm lcmtypes/route_table_t.lcm lcmtypes/route_tree_t.lcm \
	lcmtypes/flow_entry_t.lcm lcmtypes/flow_list_t.lcm

lcm-gen --cpp lcmtypes/route2_*.lcm

