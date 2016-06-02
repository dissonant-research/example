#!/usr/bin/env python
import angr

GOAL_ADDR = 0x40292c	# Find a path that executes this address.
						# GOAL_ADDR accesses the string to be printed on success.

AVOID_ADDR = 0x402941	# Exclude paths that execute this address.
						# AVOID_ADDR accesses the string to be printed on failure.

FLAG_SIZE = 0x34		# 0x4 * 0xd = 0x34
						# Disassembly showed that each flag value
						# place on the stack is of size 0x4,
						# and there are 13 values in the flag.

# Load the binary into an angr project.
# auto_load_libs is set to false, so we're not loading dynamic libs to analyze too.
proj = angr.Project('./baby-re', load_options={"auto_load_libs": False})

# Begin with the initial entry state to the binary.
initial_state = proj.factory.entry_state()
initial_path = proj.factory.path(initial_state)
path_group = proj.factory.path_group(initial_state)

# Setup the execution path explorer.
# Search execution paths that lead to GOAL_ADDR.
# Exclude execution paths that lead to AVOID_ADDR.
explorer = proj.surveyors.Explorer(start=initial_path, find=(GOAL_ADDR,), avoid=(AVOID_ADDR,))

# Explore the binary.
explorer.run()

# explorer.found[] is a list of discovered solution.
# explorer._f just points to the first solution.
# For this binary, we only expect one solution (one possible flag of printable characters).
state = explorer._f.state

# Disassembling the binary showed that each scanf value
# is contiguously copied to the stack starting at [rbp-0x60].
# If all values are verified as correct, baby-re prints them as the flag.
FLAG = state.regs.rbp - 0x60

print "Solution:", "\"" + state.se.any_str(state.memory.load(FLAG, FLAG_SIZE)) + "\""

