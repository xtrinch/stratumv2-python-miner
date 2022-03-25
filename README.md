# Mining controller

Simple python bitcoin miner with stratum2

It supports the following scenarios:

```
Miner (V2) ----> pool (V2)
```

# Running

Create virtualenv with `python3 -m venv env`.
Run `source env/bin/activate`.
Run `pip install -r requirements.txt`.

Run pool with `python3 simulate-pool.py` and miner with `python3 mine.py`.

# Overview

The protocol used is **Stratum V2**. The basis for this repository is https://github.com/braiins/braiins/tree/bos-devel/open/protocols/stratum/sim.

# Features

- Basic bitcoin mining via stratum 2 protocol


## Install

Requires Python 3.7.