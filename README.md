# Mining controller

Simple python bitcoin miner with stratum2. It sure isn't fast as it's written in python, but this is just a proof of concept for stratum2 mining as there's no other examples I could find on github.

It supports the following scenarios:

```
Miner (V2) ----> pool (V2)
```

It includes a simulation of a pool and an actual miner client. Ideally, you run them both, you can also run the miner against a real stratum server (you can find some @ slushpool) but you may get banned for not producing any valid shares after a while.

# Running

- Create virtualenv with `python3 -m venv env`.
- Run `source env/bin/activate`.
- Run `pip install -r requirements.txt`.

Run pool with `python3 simulate-pool.py` and miner with `python3 mine.py`.

# Overview

The protocol used is **Stratum V2**. The basis for this repository is https://github.com/braiins/braiins/tree/bos-devel/open/protocols/stratum/sim.

# Features

- Basic bitcoin mining via stratum 2 protocol


## Install

Requires Python 3.7.
