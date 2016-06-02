# A simple angr example (with a little radare2)
I'm interested in understanding how to use angr better.

I'm also interested in playing with radare.

In this example, I used radare as the primary disassembler, and angr to perform concolic analysis.

## the goal
baby-re is a challenge binary from the [2016 DEFCON Qualifier CTF, provided by LBS](https://github.com/legitbs/quals-2016/tree/master/baby-re). 

It's a 64-bit ELF for Linux.

When run, it prompts the user to enter values for Var0, Var1, Var2, ..., Var12.

If anything incorrect is entered, it stops and exits. 

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/ui.png)

## disassembling
main() is very simple. Take a look at the [radare2 disassembly in main.dis](https://github.com/dissonant-research/examples/blob/master/angr/main.dis).

It reads in Var0-Var12 using scanf, then checks the values using a CheckSolution() function. On success, it will print out a success message with the flag string. On failure, it prints out "Wrong". That's the wrong program.

Here's a screenshot showing a portion of main(). It's calling CheckSolution() on the input values, then accessing the solution/failure strings, based on the return result:
![](https://raw.githubusercontent.com/dissonant-research/examples/8c4d774754126b89e2a321806ef7ebb3ff3d463e/angr/main1.png "Very Simple")

Looking at CheckSolution(), things get a significantly more hairy, fast. It becomes quickly obvious that this is the bulk of the program, by a significant margin. CheckSolution() is about 9 times larger than main(). [Here is radare2's disassembly of the function](https://github.com/dissonant-research/examples/blob/master/angr/check-solution.dis).

You can also look at the sheer size of the basic block graph when zoomed all the way out (generated using IDA):
![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/baby-re-CheckSolution-bbgraph.png)

According to LBS's write-up of the source, they are asking you to input coefficients for a set of linear equations. When the correct coefficients are found, CheckSolution() will generate the flag to be printed. This would normally require reverse engineering the function to the point where an algebraic model can be created to reach the solution.

[In fact, here's the original source code.](https://raw.githubusercontent.com/legitbs/quals-2016/master/baby-re/baby-re.c)

That looks like a lot of work, especially when the source code wasn't available. Which leads us to...

## angr
Doing things by hand is hard; luckily, we have plenty of angr. Angr contains a symbolic analysis engine for automatically modeling code logic, and path-finders to look for a defined solution state by using that symbolic modeling with concrete values (hence, "concolic").

We already have everything we need to know about the binary in order to find a flag. We know that executing 0x0040292c grabs the success string to be printed, and executing 0x402941 grabs the failure string to be printed. We have no idea what the state of each of the 13 characters will be when it reaches a success state, but that doesn't matter; we can let angr grind away for possible values which will satisfy a path to 0x0040292c, while avoiding any paths that lead to 0x402941.

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/source_shot.png)

Using angr's python interface, it was possible to quickly develop [baby-re-simple.py](https://github.com/dissonant-research/examples/blob/master/angr/baby-re-simple.py), which finds a solution in about 3:45 minutes on my workstation.

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/angr_time.png)

"Math is hard!" turned out to be the solution for satisfying the system of linear equations in CheckSolution(), and we were able to determine that using a generic binary analysis tool within a few miutes, versus reverse engineering the equations by hand.

By mapping the ASCII values back into integers, we can run baby-re again and verify the correct values:

![](https://raw.githubusercontent.com/dissonant-research/examples/master/angr/solution_ui.png)
