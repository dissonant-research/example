#!/usr/bin/env python

import angr

GOAL_ADDR = 0x40292c	# find a path that executes this address
AVOID_ADDR = 0x402941	# never execute this address

proj = angr.Project('./baby-re', load_options={"auto_load_libs": False})

initial_state = proj.factory.entry_state(args=["./baby-re"])
initial_path = proj.factory.path(initial_state)
path_group = proj.factory.path_group(initial_state)

# Setup the execution path explorer.
explorer = proj.surveyors.Explorer(start=initial_path, find=(GOAL_ADDR,), avoid=(AVOID_ADDR,))

# Explore the binary.
# Search execution paths that lead to GOAL_ADDR.
# Exclude execution paths that lead to AVOID_ADDR.
explorer.run()

# explorer.found is a list of discovered solutions.
# explorer._f points to the first solution state.
# For this binary, we only expect one solution (a flag of printable characters).
state = explorer._f.state

# Disassembly showed that each scanf value is copied to the stack starting at [rbp-0x60].
FLAG = state.regs.rbp - 0x60

# Disassembly showed that each stack element is 0x4, and we know there are 13 of them.
# 0x4 * 0xd = 0x34
FLAG_SIZE = 0x34

print "Solution:", "\"" + state.se.any_str(state.memory.load(FLAG, FLAG_SIZE)) + "\""

