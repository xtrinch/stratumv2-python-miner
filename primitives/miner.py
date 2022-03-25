import asyncio  # new module
import concurrent.futures
import enum
import math
import time
from hashlib import sha256

import numpy as np
import simpy
from colorama import Fore, Style
from event_bus import EventBus

import primitives.coins as coins
from primitives.connection import Connection
from primitives.hashrate_meter import HashrateMeter
from primitives.messages import (
    NewMiningJob,
    OpenMiningChannelError,
    OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess,
    SetNewPrevHash,
    SetTarget,
    SetupConnection,
    SetupConnectionError,
    SetupConnectionSuccess,
    SubmitSharesError,
    SubmitSharesStandard,
    SubmitSharesSuccess,
)
from primitives.protocol import ConnectionProcessor
from primitives.session import MiningJob, MiningSession, PoolMiningChannel
from primitives.types import DownstreamConnectionFlags, ProtocolType


class Miner(ConnectionProcessor):
    class States(enum.Enum):
        INIT = 0
        CONNECTION_SETUP = 1

    def __init__(
        self,
        name: str,
        bus: EventBus,
        diff_1_target: int,
        device_information: dict,
        connection: Connection,
        *args,
        **kwargs,
    ):
        self.name = name
        self.bus = bus
        self.diff_1_target = diff_1_target
        self.device_information = device_information
        self.work_meter = HashrateMeter()
        self.mine_proc = None
        self.job_uid = None
        self.share_diff = None
        self.recv_loop_process = None

        self.state = self.States.INIT
        self.channel = None
        self.connection_config = None
        self.job = None
        self.is_mining = False

        super().__init__(self.name, self.bus, connection)

    def get_actual_speed(self):
        return self.device_information.get("speed_ghps") if self.is_mining else 0

    def _send_msg(self, msg):
        self.connection.send_msg(msg)

    def int_to_reverse_bytes(self, num: int, byteno: int):
        reverse_bytes = num.to_bytes(byteno, byteorder="little")
        return reverse_bytes

    # assemble header without nonce, so we can just append it
    def assemble_header(
        self,
        version: int,
        prev_hash: bytes,
        merkle_root: bytes,
        ntime: int,
        nbits: int,
    ):
        header = (
            self.int_to_reverse_bytes(version, 4)
            + prev_hash  # 32 bytes
            + merkle_root  # 32 bytes
            + self.int_to_reverse_bytes(ntime, 4)
            + self.int_to_reverse_bytes(nbits, 4)
        )
        return header

    def mine(self, job: MiningJob):
        share_diff = job.diff_target.to_difficulty()
        avg_time = share_diff * 4.294967296 / self.device_information.get("speed_ghps")

        # Report the current hashrate at the beginning when of mining
        self.__emit_hashrate_msg_on_bus(job, avg_time)

        nonce = 0
        min_hash = 0xFFFF << 224

        # version: from NewMiningJob message
        # prev_hash: from SetNewPrevHash message
        # merkle_root: from NewMiningJob message
        # ntime: from SetNewPrevHash message (min_ntime)
        # nbits: from SetNewPrevHash message
        # nonce: auto incremented value
        header_without_nonce = self.assemble_header(
            version=job.version,
            prev_hash=self.channel.session.prev_hash,
            merkle_root=job.merkle_root,
            ntime=self.channel.session.min_ntime,
            nbits=self.channel.session.nbits,
        )

        job.started_at = int(time.time())
        print("Max target:")
        print((0xFFFF << 208).to_bytes(32, byteorder="big").hex())
        print("Curr target:")
        print(
            self.channel.session.curr_target.target.to_bytes(32, byteorder="big").hex()
        )
        print("--------------")
        while not job.is_cancelled:
            # assemble the header
            full_header = header_without_nonce + self.int_to_reverse_bytes(nonce, 4)

            hash_bytes = sha256(sha256(full_header).digest()).digest()
            hash = int.from_bytes(hash_bytes, byteorder="little")

            if hash < min_hash:
                print(hash.to_bytes(32, byteorder="big").hex())
                min_hash = hash

            if hash < self.channel.session.curr_target.target:
                self.__emit_aux_msg_on_bus("solution found for job {}".format(job.uid))
                self.work_meter.measure(share_diff)
                self.__emit_hashrate_msg_on_bus(job, avg_time)
                self.submit_mining_solution(job)

            nonce += 1

        job.finished_at = int(time.time())
        print(
            "Job duration: %d sec, nonce is at %d" % job.finished_at - job.started_at,
            nonce,
        )

    async def connect_to_pool(self, connection: Connection):
        self.__emit_aux_msg_on_bus(
            "Connecting to pool {}:{}".format(
                connection.pool_host, connection.pool_port
            )
        )

        await connection.connect_to_pool()

        self.__emit_aux_msg_on_bus("Connected!")

        # Intializes MinerV2 instance
        self.setup_connection()

    def disconnect(self):
        self.__emit_aux_msg_on_bus("Disconnecting from pool")
        if self.mine_proc:
            self.mine_proc.interrupt()
        # Mining is shutdown, terminate any protocol message processing
        self.terminate()
        self.disconnect()
        self.miner = None

    def new_mining_session(self, diff_target: coins.Target):
        """Creates a new mining session"""
        session = MiningSession(
            name=self.name,
            bus=self.bus,
            # TODO remove once the backlinks are not needed
            owner=None,
            diff_target=diff_target,
            enable_vardiff=False,
        )
        self.__emit_aux_msg_on_bus("NEW MINING SESSION ()".format(session))
        return session

    def mine_on_new_job(self, job: MiningJob, flush_any_pending_work=True):
        """Start working on a new job

        TODO implement more advanced flush policy handling (e.g. wait for the current
         job to finish if flush_flush_any_pending_work is not required)
        """
        # Interrupt the mining process for now
        if self.mine_proc is not None:
            self.job.is_cancelled = True
            self.mine_proc.cancel()
        # Restart the process with a new job
        self.job = job
        self.set_is_mining(True)

        # create the mining task for this job
        loop = asyncio.get_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        def m():
            self.mine(job)

        task = loop.run_in_executor(executor, m)
        self.mine_proc = task

    def set_is_mining(self, is_mining):
        self.is_mining = is_mining

    def __emit_aux_msg_on_bus(self, msg: str):
        print(
            f"{Fore.BLUE}{Style.BRIGHT}%s: {Style.NORMAL}%s{Style.RESET_ALL}"
            % (self.name, msg)
        )

    def __emit_hashrate_msg_on_bus(self, job: MiningJob, avg_share_time):
        """Reports hashrate statistics on the message bus

        :param job: current job that is being mined
        :return:
        """
        self.__emit_aux_msg_on_bus(
            "mining with diff. {} | speed {} Gh/s | avg share time {} | job uid {}".format(
                job.diff_target.to_difficulty(),
                self.work_meter.get_speed(),
                avg_share_time,
                job.uid,
            )
        )

    def setup_connection(self):
        self.connection.send_msg(
            SetupConnection(
                protocol=ProtocolType.MINING_PROTOCOL,
                max_version=2,
                min_version=2,
                flags=0,  # TODO:
                endpoint_host=self.connection.pool_host,
                endpoint_port=self.connection.pool_port,
                vendor=self.device_information.get("vendor", "unknown"),
                hardware_version=self.device_information.get(
                    "hardware_version", "unknown"
                ),
                firmware=self.device_information.get("firmware", "unknown"),
                device_id=self.device_information.get("device_id", ""),
            )
        )

    class ConnectionConfig:
        """Stratum V2 connection configuration.

        For now, it is sufficient to record the SetupConnectionSuccess to have full
        connection configuration available.
        """

        def __init__(self, msg: SetupConnectionSuccess):
            self.setup_msg = msg

    def _recv_msg(self):
        return self.connection.incoming.get()

    def disconnect(self):
        """Downstream node may initiate disconnect"""
        self.connection.disconnect()

    def _on_invalid_message(self, msg):
        pass

    def visit_setup_connection_success(self, msg: SetupConnectionSuccess):
        self.connection_config = self.ConnectionConfig(msg)
        self.state = self.States.CONNECTION_SETUP

        req = OpenStandardMiningChannel(
            req_id=1,
            user_identity=self.name,
            nominal_hash_rate=math.floor(
                self.device_information.get("speed_ghps") * 1e9
            ),
            # TODO: figure this out
            max_target=self.diff_1_target,
        )
        # We expect a paired response to our open channel request
        self.send_request(req)

    def visit_setup_connection_error(self, msg: SetupConnectionError):
        """Setup connection has failed.

        TODO: consider implementing reconnection attempt with exponential backoff or
         something similar
        """
        self._emit_protocol_msg_on_bus("Connection setup failed", msg)

    def visit_open_standard_mining_channel_success(
        self, msg: OpenStandardMiningChannelSuccess
    ):
        req = self.request_registry.pop(msg.req_id)

        if req is not None:
            session = self.new_mining_session(
                coins.Target(msg.target, self.diff_1_target)
            )
            # TODO find some reasonable extraction of the channel configuration, for now,
            #  we just retain the OpenMiningChannel and OpenMiningChannelSuccess message
            #  pair that provides complete information
            self.channel = PoolMiningChannel(
                session=session,
                # cfg=(req, msg),
                cfg=msg,
                conn_uid=self.connection.uid,
                channel_id=msg.channel_id,
            )
            session.run()
        else:
            self._emit_protocol_msg_on_bus(
                "Cannot find matching OpenMiningChannel request", msg
            )

    def visit_open_extended_mining_channel_success(
        self, msg: OpenStandardMiningChannelSuccess
    ):
        pass

    def visit_open_mining_channel_error(self, msg: OpenMiningChannelError):
        req = self.request_registry.pop(msg.req_id)
        self._emit_protocol_msg_on_bus(
            "Open mining channel failed (orig request: {})".format(req), msg
        )

    def visit_set_target(self, msg: SetTarget):
        if self.__is_channel_valid(msg):
            self.channel.session.set_target(
                coins.Target(
                    msg.max_target, self.channel.session.curr_diff_target.diff_1_target
                )
            )

    def visit_set_new_prev_hash(self, msg: SetNewPrevHash):
        if self.__is_channel_valid(msg):
            if self.channel.session.job_registry.contains(msg.job_id):
                job = self.channel.session.job_registry.get_job(msg.job_id)
                # retire all other jobs, as only the referenced job is valid
                self.channel.session.job_registry.retire_all_jobs()
                self.channel.session.set_prev_hash(msg)

                self.mine_on_new_job(
                    job=job,
                    flush_any_pending_work=True,
                )

    def visit_new_mining_job(self, msg: NewMiningJob):
        if self.__is_channel_valid(msg):
            # Prepare a new job with the current session difficulty target
            job = self.channel.session.new_mining_job(
                version=msg.version, merkle_root=msg.merkle_root, job_uid=msg.job_id
            )
            # Schedule the job for mining
            if not msg.future_job:
                self.mine_on_new_job(job)

    def visit_submit_shares_success(self, msg: SubmitSharesSuccess):
        if self.__is_channel_valid(msg):
            self.channel.session.account_diff_shares(msg.new_shares_sum)

    def visit_submit_shares_error(self, msg: SubmitSharesError):
        if self.__is_channel_valid(msg):
            # TODO implement accounting for rejected shares
            pass
            # self.channel.session.account_rejected_shares(msg.new_shares_sum)

    def submit_mining_solution(self, job: MiningJob):
        """Callback from the physical miner that succesfully simulated mining some shares

        :param job: Job that the miner has been working on and found solution for it
        """
        # TODO: seq_num is currently unused, we should use it for tracking
        #  accepted/rejected shares
        self._send_msg(
            SubmitSharesStandard(
                channel_id=self.channel.id,
                sequence_number=0,  # unique sequential identifier within the channel.
                job_id=job.uid,
                nonce=0,
                ntime=0,  # self.env.now,
                version=0,  # full nVersion field
            )
        )

    def _on_invalid_message(self, msg):
        self._emit_protocol_msg_on_bus("Received invalid message", msg)

    def __is_channel_valid(self, msg):
        """Validates channel referenced in the message is the open channel of the miner"""
        if self.channel is None:
            bus_error_msg = (
                "Mining Channel not established yet, received channel "
                "message with channel ID({})".format(msg.channel_id)
            )
            is_valid = False
            self._emit_protocol_msg_on_bus(bus_error_msg, msg)
        elif self.channel.channel_id != msg.channel_id:
            bus_error_msg = "Unknown channel (expected: {}, actual: {})".format(
                self.channel.id, msg.channel_id
            )
            is_valid = False
            self._emit_protocol_msg_on_bus(bus_error_msg, msg)
        else:
            is_valid = True

        return is_valid
