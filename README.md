# CodeTree

This will parse a VICE VSF snapshot, and generate a code calling tree. It does its best to split out and analyse code structure. You need to give it starting points. It doesn't work out 
bne
beq

bpl
bmi
etc
pairs form a "jmp" so you can give it a force stop location after said pairs once you identify them. You can give it a regenerator config file for it to use the code and data segments + labels in the graphs. 

Python 3.x
needs graphviz package https://pypi.org/project/graphviz/

run for usage instructions.

