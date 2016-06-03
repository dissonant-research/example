# A simple angr example (with a little radare2)
I'm interested in better understanding angr.

I'm also interested in playing with radare2.

In this example, I used radare as the disassembler, to learn how to navigate binaries with it. I found [this summary](https://github.com/pwntester/cheatsheets/blob/master/radare2.md) to be extremely useful.

And I used angr to perform concolic analysis, with a particular goal in mind. 

[Here is an explanation of angr.](http://angr.io/)

## Goal
baby-re is a challenge binary from the 2016 DEFCON Qualifier CTF, provided by LBS. 

It's a 64-bit ELF for Linux.

When run, it prompts the user to enter values for Var[0], Var[1], Var[2], ..., Var[12].

If anything incorrect is entered, it stops and exits. 

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/ui.png)

We want to figure out what to input, to keep it from being wrong.

That's everything on the surface.

## Disassembling
main() is very simple. Take a look at the [radare2 disassembly in main.dis](https://github.com/dissonant-research/examples/blob/master/angr/main.dis).

The primary support function, CheckSolution(), is less simple. Take a look at the [radare2 disassembly in check-solution.dis](https://github.com/dissonant-research/random-work/blob/master/angr/check-solution.dis).

```main()``` reads in Var[0]-Var[12] using scanf, then verifies the values using CheckSolution(). On success, it will print out a success message with the flag string. On failure, it prints out "Wrong". That's the whole program. Super simple.

Here's a screenshot showing a portion of main(). It's calling CheckSolution() on the input values, then accessing the solution/failure strings, based on the return result:

![](https://raw.githubusercontent.com/dissonant-research/examples/8c4d774754126b89e2a321806ef7ebb3ff3d463e/angr/main1.png "Very Simple")

So, we drill into CheckSolution(), to determine which values the binary is looking for. Things get hairier at this point; CheckSolution() is about 9 times larger than main(). It's obfuscates the check by performing a large number of arithmetic operations on the input values, before checking them against some constants. This is essentially a hashing mechanism, but doesn't appear to be cryptographic in strength.

Here's the function's zoomed-out basic block graph (generated using IDA):
![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/baby-re-CheckSolution-bbgraph.png)

That looks like a lot of work, though. Especially when the source code wasn't available. Which leads us to...

## Angr
Doing things by hand is time consuming; luckily, we have plenty of angr. Angr contains a symbolic analysis engine for automatically modeling code logic and finding paths to a concrete solution state. ("Concolic" is a portmanteau of "concrete" & "symbolic.")

Therefore, we already have everything we need to know about the binary in order to find a flag. We don't have to reverse engineer the linear equations by hand. We see that executing 0x0040292c accesses the success string to be printed, while executing 0x402941 accesses the failure string to be printed. We have no idea what the state of each of the 13 characters will be when it reaches a success state, but that doesn't matter; we can let angr grind away for possible values which will satisfy a path to 0x0040292c. To help it along, we can also tell angr to explicitly avoid any paths that lead to 0x402941.

Using angr's python interface, it was possible to [quickly develop baby-re-simple.py](https://github.com/dissonant-research/examples/blob/master/angr/baby-re-simple.py), which finds a solution in less than four minutes on my workstation.

```python
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
```

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/angr_time.png)

This is essentially a brute-force solution, in terms of symbolic analysis; we didn't provide any concreteness aside from the execution address we wanted to find a path to. While CheckSolution() would have taken a while to reverse engineer by hand, it's not strong obfuscation. If the author had chosen to use a (cryptographic) hash function on the inputs, then checked the result against a stored hash, this wouldn't have been nearly so easy. (As an aside, a true brute-force approach would have required searching through the full space of 13 printable characters, of which there are around 4.47x10<sup>25</sup>.)

As you can see above, "Math is hard!" turned out to be the solution for satisfying the system of linear equations in CheckSolution(). By mapping the ASCII values back into integers, we can run baby-re again and verify the correct values:

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/solution_ui.png)

## Source Code
According to [LBS's post-competition release](https://github.com/legitbs/quals-2016/tree/master/baby-re) (not available during the CTF, obviously), the Var[0]-Var[12] inputs are coefficients for a set of linear equations defined in CheckSolution(). When the correct coefficients are entered, CheckSolution() verifies them as character values of the flag, and main() prints them. This would normally require reverse engineering CheckSolution() to recreate the linear equations and solve them.

[Here's the original C source.](https://raw.githubusercontent.com/legitbs/quals-2016/master/baby-re/baby-re.c)
