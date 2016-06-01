# A Simple angr Example
I'm interested in understanding how to use angr better.

I'm also interested in playing with radare.

In this example, I used radare as the primary disassembler, and angr to perform concolic analysis.

## the goal
baby-re is a challenge binary from the [https://github.com/legitbs/quals-2016/tree/master/baby-re](2016 DEFCON Qualifier CTF, provided by LBS). 

It's a 64-bit ELF for Linux.

When run, it prompts the user to enter values for Var0, Var1, Var2, ..., Var12.

If anything incorrect is entered, it stops and exits. 

## disassembling
main() is very simple. Take a look at the [https://github.com/dissonant-research/examples/blob/master/angr/main.dis](radare2 disassembly in main.dis).

It reads in Var0-Var12 using scanf, then checks the values using a CheckSolution() function. On success, it will print out a success message with the flag string. On failure, it prints out "Wrong". That's the wrong program.

Looking at CheckSolution(), things get a significantly more hairy, fast. You can see this from the [https://raw.githubusercontent.com/dissonant-research/examples/master/angr/baby-re-CheckSolution-bbgraph.png](sheer size of the basic block graph) (bb graph generated using IDA), as well as  [https://github.com/dissonant-research/examples/blob/master/angr/check-solution.dis](going through the disassembly).

According to LBS's write-up of the source, they are asking you to input coefficients for a set of linear equations. When the correct coefficients are found, CheckSolution() will generate the flag to be printed. This would normally require reverse engineering the function to the point where an algebraic model can be created to reach the solution.

That sounds like a lot of work.

## angr
However, we have angr. And angr contains a symbolic analysis engine for automatically modeling code logic, to look for a defined solution state.

We already have everything we need to know about the binary in order to find a flag. We know that executing 0x0040292c grabs the success string to be printed, and executing 0x402941 grabs the failure string to be printed. We have no idea what the state of each of the 13 characters will be when it reaches a success state, but that doesn't matter; we can let angr grind away for any possible values which will satisfy a path to 0x0040292c, while avoiding any paths that lead to 0x402941.

Using angr's python interface, [https://github.com/dissonant-research/examples/blob/master/angr/baby-re-simple.py](baby-re-simple.py is a simple solution) which finds a solution in about 3.5 miutes on my workstation.

