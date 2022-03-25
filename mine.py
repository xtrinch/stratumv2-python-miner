import argparse
import asyncio  # new module
import logging
import time
import traceback

import numpy as np
import simpy
from colorama import Fore, init
from event_bus import EventBus

import primitives.coins as coins
import primitives.mining_params as mining_params
from primitives.connection import Connection
from primitives.miner import Miner
from primitives.pool import Pool

init()
bus = EventBus()


async def connect():
    np.random.seed(123)
    parser = argparse.ArgumentParser(
        prog="mine.py",
        description="Simulates interaction of a mining pool and two miners",
    )
    parser.add_argument(
        "--realtime",
        help="run simulation in real-time (otherwise is run as fast as possible)",
        action="store_const",
        const=True,
    )
    parser.add_argument(
        "--rt-factor",
        help="real-time simulation factor, default=1 (enter 0.5 to be twice as fast than the real-time",
        type=float,
        default=1,
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="simulation time limit in seconds, default = 500",
        default=50,
    )
    parser.add_argument(
        "--verbose",
        help="display all events (warning: a lot of text is generated)",
        action="store_const",
        const=True,
    )

    parser.add_argument(
        "--plain-output",
        help="Print just values to terminal: accepted shares, accepted submits,"
        " stale shares, stale submits, rejected submits",
        action="store_true",
    )

    args = parser.parse_args()

    if args.verbose:

        @bus.on("miner1")
        def subscribe_m1(ts, conn_uid, message):
            print(
                Fore.LIGHTRED_EX,
                "T+{0:.3f}:".format(ts),
                "(miner1)",
                conn_uid if conn_uid is not None else "",
                message,
                Fore.RESET,
            )

    conn1 = Connection(
        "miner",
        "stratum",
        # pool_host="v2.eu.stratum.slushpool.com",
        # pool_port=3336,
        pool_host="localhost",
        pool_port=2000,
    )

    m1 = Miner(
        "xtrinch.worker",
        bus,
        diff_1_target=mining_params.diff_1_target,
        device_information=dict(
            speed_ghps=0.000250,  # 250.000 hashes per second
            vendor="python",
            hardware_version="PC",
            firmware="python-miner",
            device_id="xtrinch.worker",
        ),
        connection=conn1,
    )

    await m1.connect_to_pool(conn1)

    return m1, conn1


async def main():
    (m1, conn1) = await connect()

    await m1.receive_loop()


if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG)

    asyncio.run(main())
