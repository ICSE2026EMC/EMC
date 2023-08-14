README

# DMC

A Robust Windows Malware Classification Refinement for Concept Drift.


##Setup

* `IDA Pro`: >= 7.5
* `pytorch`==1.7.0 
* `cudatoolkit`=11.1
* `datasets`==1.18.3
* `transformers`==4.16.2
* `tensorboard`==2.8.0

## USEAGE

Disassembly

Put the `auto_opcode.py` `call_opcode.py` `ida_opcode.py` in the IDA Pro working directory and run
```
python auto_opcode.py
```

Feature Decorrelation
```
python main_FeatDe.py
```

Feature Decorrelation and Purification
```
python main_DePro.py
```
