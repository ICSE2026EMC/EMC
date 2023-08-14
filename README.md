README

# DMC

A Robust Windows Malware Classification Refinement for Concept Drift.


## Setup

* `IDA Pro`: >= 7.5
* `pytorch`==1.7.0 
* `cudatoolkit`=11.1
* `datasets`==1.18.3
* `transformers`==4.16.2
* `tensorboard`==2.8.0

## Dataset

The dataset `MalwareBazaar` `MalwareDrift` and label files `MalwareBazaar_Labels.csv` `MalwareBazaar_Labels.csv` used in this paper and code come from the following paper.

\[FSE2021\] [A Comprehensive Study on Learning-Based PE Malware Family Classification Methods.](https://dl.acm.org/doi/abs/10.1145/3468264.3473925)

Code:<https://github.com/MHunt-er/Benchmarking-Malware-Family-Classification>




## Useage

Disassembly


Put the `auto_opcode.py` `call_opcode.py` `ida_opcode.py` in the IDA Pro working directory and run
```
python auto_opcode.py
```

Feature Process

```
python opc_trans_sen.py
```

Feature Decorrelation
```
python main_FeatDe.py
```

Feature Decorrelation and Purification
```
python main_DePro.py
```
