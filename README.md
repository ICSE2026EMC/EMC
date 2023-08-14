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


Put the `auto_opcode.py` `call_opcode.py` `ida_opcode.py` in the IDA Pro working directory. 

Put the raw malware binary files in the `pefile_dir` and run
```
python auto_opcode.py
```

Feature Process

Put the output of `auto_opcode.py` in the `folder_path` and run
```
python opc_trans_sen.py
```

Feature Decorrelation

Put the training and verification feature vectors processed by `opc_trans_sen.py` under path `traindir` `valdir`, and run
```
python main_FeatDe.py
```

Feature Decorrelation and Purification

Put the training and verification feature vectors processed by `opc_trans_sen.py` under path `traindir` `valdir`, and run
```
python main_DePro.py
```
