"""Generic pool module"""
import base64
import hashlib
import socket
import time

import numpy as np
import simpy
from colorama import Fore, Style
from cryptography.hazmat.primitives.asymmetric import x25519
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.processing.handshakepatterns.interactive.NX import NXHandshakePattern
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from event_bus import EventBus

import primitives.coins as coins
from primitives.connection import Connection
from primitives.hashrate_meter import HashrateMeter
from primitives.protocol import ConnectionProcessor

"""Stratum V2 pool implementation

"""
import asyncio
import random
from asyncio import StreamReader, StreamWriter

import primitives.coins as coins
from primitives.messages import *
from primitives.protocol import ConnectionProcessor
from primitives.session import (
    ChannelRegistry,
    MiningChannel,
    MiningJob,
    MiningJobRegistry,
    MiningSession,
    PoolMiningChannel,
)
from primitives.types import DownstreamConnectionFlags, UpstreamConnectionFlags


class Pool(ConnectionProcessor):
    """Represents a generic mining pool.

    It handles connections and delegates work to actual protocol specific object

    The pool keeps statistics about:

    - accepted submits and shares: submit count and difficulty sum (shares) for valid
    solutions
    - stale submits and shares: submit count and difficulty sum (shares) for solutions
    that have been sent after new block is found
    - rejected submits: submit count of invalid submit attempts that don't refer any
    particular job
    """

    meter_period = 60

    def __init__(
        self,
        name: str,
        bus: EventBus,
        default_target: coins.Target,
        extranonce2_size: int = 8,
        avg_pool_block_time: float = 60,
        enable_vardiff: bool = False,
        desired_submits_per_sec: float = 0.3,
    ):
        """

        :type pool_v2:
        """
        self.name = name
        self.bus = bus
        self.default_target = default_target
        self.extranonce2_size = extranonce2_size
        self.avg_pool_block_time = avg_pool_block_time

        # Prepare initial prevhash for the very first
        self.__generate_new_prev_hash()
        # Per connection message processors
        self.connection_processors = dict()

        self.meter_accepted = HashrateMeter()
        self.meter_rejected_stale = HashrateMeter()
        # self.meter_process = env.process(self.__pool_speed_meter())
        self.meter_process = None
        self.enable_vardiff = enable_vardiff
        self.desired_submits_per_sec = desired_submits_per_sec

        self.extra_meters = []

        self.accepted_submits = 0
        self.stale_submits = 0
        self.rejected_submits = 0

        self.accepted_shares = 0
        self.stale_shares = 0
        self._mining_channel_registry = None
        self.server = None

    async def client_connected_cb(
        self, client_reader: StreamReader, client_writer: StreamWriter
    ):
        print("Accepted client connection")

        # our_private = base64.b64decode('WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=')
        # private = x25519.X25519PrivateKey.from_private_bytes(our_private)

        # prepare handshakestate objects for initiator and responder
        our_handshakestate = HandshakeState(
            SymmetricState(
                CipherState(
                    # AESGCMCipher()
                    ChaChaPolyCipher()  # chacha20poly1305
                ),
                Blake2sHash(),
            ),
            X25519DH(),
        )

        pool_s = X25519DH().generate_keypair()
        our_handshakestate.initialize(NXHandshakePattern(), False, b"", s=pool_s)

        # wait for empty message receive
        ciphertext = await client_reader.read(4096)
        frame, _ = Connection.unwrap(ciphertext)
        message_buffer = bytearray()
        our_handshakestate.read_message(frame, message_buffer)

        # when we do, respond
        ## in the buffer, there should be Signature Noise Message, but we
        ## obviously don't really know how to construct it, so we'll skip it for localhost
        message_buffer = bytearray()
        self.connection.cipherstates = our_handshakestate.write_message(
            b"", message_buffer
        )
        self.connection.cipher_state = self.connection.cipherstates[1]
        self.connection.decrypt_cipher_state = self.connection.cipherstates[0]

        message_buffer = Connection.wrap(bytes(message_buffer))
        num_sent = client_writer.write(message_buffer)

        self.connection.sock = (client_reader, client_writer)
        print("Handshake done!")

        # # create the POW task only after the client is connected
        # loop = asyncio.get_event_loop()
        # print("Beofre create")
        # task = loop.create_task(self.pow_update())
        # print("After create")

    async def start_server(self):
        self.server = await asyncio.start_server(
            self.client_connected_cb, host="localhost", port=2000
        )
        await self.server.serve_forever()

    async def make_handshake(self, connection: Connection):
        self.connection = connection
        self._mining_channel_registry = ChannelRegistry(connection.uid)

    def reset_stats(self):
        self.accepted_submits = 0
        self.stale_submits = 0
        self.rejected_submits = 0
        self.accepted_shares = 0
        self.stale_shares = 0

    def disconnect(self, connection: Connection):
        if connection.uid not in self.connection_processors:
            return
        self.connection_processors[connection.uid].terminate()
        del self.connection_processors[connection.uid]

    def new_mining_session(self, owner, on_vardiff_change, clz=MiningSession):
        """Creates a new mining session"""
        session = clz(
            name=self.name,
            bus=self.bus,
            owner=owner,
            diff_target=self.default_target,
            enable_vardiff=self.enable_vardiff,
            vardiff_time_window=self.meter_accepted.window_size,
            vardiff_desired_submits_per_sec=self.desired_submits_per_sec,
            on_vardiff_change=on_vardiff_change,
        )
        self.__emit_aux_msg_on_bus("NEW MINING SESSION ()".format(session))

        return session

    def add_extra_meter(self, meter: HashrateMeter):
        self.extra_meters.append(meter)

    def account_accepted_shares(self, diff_target: coins.Target):
        self.accepted_submits += 1
        self.accepted_shares += diff_target.to_difficulty()
        self.meter_accepted.measure(diff_target.to_difficulty())

    def account_stale_shares(self, diff_target: coins.Target):
        self.stale_submits += 1
        self.stale_shares += diff_target.to_difficulty()
        self.meter_rejected_stale.measure(diff_target.to_difficulty())

    def account_rejected_submits(self):
        self.rejected_submits += 1

    def process_submit(
        self, submit_job_uid, session: MiningSession, on_accept, on_reject
    ):
        if session.job_registry.contains(submit_job_uid):
            diff_target = session.job_registry.get_job_diff_target(submit_job_uid)
            # Global accounting
            self.account_accepted_shares(diff_target)
            # Per session accounting
            session.account_diff_shares(diff_target.to_difficulty())
            on_accept(diff_target)
        elif session.job_registry.contains_invalid(submit_job_uid):
            diff_target = session.job_registry.get_invalid_job_diff_target(
                submit_job_uid
            )
            self.account_stale_shares(diff_target)
            on_reject(diff_target)
        else:
            self.account_rejected_submits()
            on_reject(None)

    async def pow_update(self):
        """This process simulates finding new blocks based on pool's hashrate"""
        while True:
            if not self.connection.sock:
                await asyncio.sleep(5)
                continue

            self.__generate_new_prev_hash()

            self.__emit_aux_msg_on_bus("NEW_BLOCK: {}".format(self.prev_hash.hex()))

            for connection_processor in self.connection_processors.values():
                connection_processor.on_new_block()

            await asyncio.sleep(5)

    def __generate_new_prev_hash(self):
        """Generates a new prevhash based on current time."""
        # TODO: this is not very precise as to events that would trigger this method in
        #  the same second would yield the same prev hash value,  we should consider
        #  specifying prev hash as a simple sequence number
        self.prev_hash = hashlib.sha256(bytes(random.randint(0, 16777216))).digest()

    def __pool_speed_meter(self):
        while True:
            # yield self.env.timeout(self.meter_period)
            speed = self.meter_accepted.get_speed()
            submit_speed = self.meter_accepted.get_submit_per_secs()
            if speed is None or submit_speed is None:
                self.__emit_aux_msg_on_bus("SPEED: N/A Gh/s, N/A submits/s")
            else:
                self.__emit_aux_msg_on_bus(
                    "SPEED: {0:.2f} Gh/s, {1:.4f} submits/s".format(speed, submit_speed)
                )

    def __emit_aux_msg_on_bus(self, msg: str):
        print(
            f"{Fore.BLUE}{Style.BRIGHT}%s: {Style.NORMAL}%s{Style.RESET_ALL}"
            % (self.name, msg)
        )

    def _send_msg(self, msg):
        self.connection.send_msg(msg)

    def _recv_msg(self):
        return self.connection.outgoing.get()

    def terminate(self):
        super().terminate()
        for channel in self._mining_channel_registry.channels:
            channel.terminate()

    def _on_invalid_message(self, msg):
        """Ignore any unrecognized messages.

        TODO-DOC: define protocol handling of unrecognized messages
        """
        pass

    def visit_setup_connection(self, msg: SetupConnection):
        # response_flags = set()

        # arbitrary for now
        # if DownstreamConnectionFlags.REQUIRES_VERSION_ROLLING not in msg.flags:
        # response_flags.add(UpstreamConnectionFlags.REQUIRES_FIXED_VERSION)
        self._send_msg(
            SetupConnectionSuccess(
                used_version=min(msg.min_version, msg.max_version),
                flags=0,
            )
        )

    def visit_open_standard_mining_channel(self, msg: OpenStandardMiningChannel):
        # Open only channels compatible with this node's configuration
        if msg.max_target <= self.default_target.diff_1_target:
            # Create the channel and build back-links from session to channel and from
            # channel to connection
            mining_channel = PoolMiningChannel(
                cfg=msg, conn_uid=self.connection.uid, channel_id=None, session=None
            )
            # Appending assigns the channel a unique ID within this connection
            self._mining_channel_registry.append(mining_channel)

            # TODO use partial to bind the mining channel to the _on_vardiff_change and eliminate the need for the
            #  backlink
            session = self.new_mining_session(
                owner=mining_channel, on_vardiff_change=self._on_vardiff_change
            )
            mining_channel.set_session(session)

            self._send_msg(
                OpenStandardMiningChannelSuccess(
                    req_id=msg.req_id,
                    channel_id=mining_channel.id,
                    target=session.curr_target.target,
                    extranonce_prefix=b"",
                    group_channel_id=0,  # pool currently doesn't support grouping
                )
            )

            # TODO-DOC: explain the (mandatory?) setting 'future_job=True' in
            #  the message since the downstream has no prev hash
            #  immediately after the OpenStandardMiningChannelSuccess
            #  Update the flow diagram in the spec including specifying the
            #  future_job attribute
            new_job_msg = self.__build_new_job_msg(mining_channel, is_future_job=True)
            # Take the future job from the channel so that we have space for producing a new one right away
            future_job = mining_channel.take_future_job()
            assert (
                future_job.uid == new_job_msg.job_id
            ), "BUG: future job on channel {} doesn't match the produced message job ID {}".format(
                future_job.uid, new_job_msg.job_id
            )
            self._send_msg(new_job_msg)
            self._send_msg(
                self.__build_set_new_prev_hash_msg(
                    channel_id=mining_channel.id, future_job_id=new_job_msg.job_id
                )
            )
            # Send out another future job right away
            future_job_msg = self.__build_new_job_msg(
                mining_channel, is_future_job=True
            )
            self._send_msg(future_job_msg)

            # All messages sent, start the session
            session.run()

        else:
            self._send_msg(
                OpenMiningChannelError(
                    msg.req_id, "Cannot open mining channel: {}".format(msg)
                )
            )

    def visit_submit_shares_standard(self, msg: SubmitSharesStandard):
        """
        TODO: implement aggregation of sending SubmitSharesSuccess for a batch of successful submits
        """
        channel = self._mining_channel_registry.get_channel(msg.channel_id)
        channel = self._mining_channel_registry.get_channel(msg.channel_id)

        assert channel, "Channel {} is not defined".format(msg.channel_id)

        assert (
            channel.conn_uid == self.connection.uid
        ), "Channel conn UID({}) doesn't match current conn UID({})".format(
            channel.conn_uid, self.connection.uid
        )
        self.__emit_channel_msg_on_bus(msg)

        def on_accept(diff_target: coins.Target):
            resp_msg = SubmitSharesSuccess(
                channel.id,
                last_sequence_number=msg.sequence_number,
                new_submits_accepted_count=1,
                new_shares_sum=diff_target.to_difficulty(),
            )
            self._send_msg(resp_msg)
            self.__emit_channel_msg_on_bus(resp_msg)

        def on_reject(_diff_target: coins.Target):
            resp_msg = SubmitSharesError(
                channel.id,
                sequence_number=msg.sequence_number,
                error_code="Share rejected",
            )
            self._send_msg(resp_msg)
            self.__emit_channel_msg_on_bus(resp_msg)

        self.process_submit(
            msg.job_id, channel.session, on_accept=on_accept, on_reject=on_reject
        )

    def visit_submit_shares_extended(self, msg: SubmitSharesStandard):
        pass

    def _on_vardiff_change(self, session: MiningSession):
        """Handle difficulty change for the current session.

        Note that to enforce difficulty change as soon as possible,
        the message is accompanied by generating new mining job
        """
        channel = session.owner
        self._send_msg(SetTarget(channel.id, session.curr_target.to_bytes()))

        new_job_msg = self.__build_new_job_msg(channel, is_future_job=False)
        self._send_msg(new_job_msg)

    def on_new_block(self):
        """Sends an individual SetNewPrevHash message to all channels

        TODO: it is not quite clear how to handle the case where downstream has
         open multiple channels with the pool. The following needs to be
         answered:
         - Is any downstream node that opens more than 1 mining channel considered a
           proxy = it understands  grouping? MAYBE/YES but see next questions
         - Can we send only 1 SetNewPrevHash message even if the channels are
           standard? NO - see below
         - if only 1 group SetNewPrevHash message is sent what 'future' job should
           it reference? The problem is that we have no defined way where a future
           job is being shared by multiple channels.
        """
        # Pool currently doesn't support grouping channels, all channels belong to
        # group 0. We set the prev hash for all channels at once
        # Retire current jobs in the registries of all channels
        for channel in self._mining_channel_registry.channels:
            future_job = channel.take_future_job()
            prev_hash_msg = self.__build_set_new_prev_hash_msg(
                channel.id, future_job.uid
            )
            channel.session.job_registry.retire_all_jobs()
            channel.session.job_registry.add_job(future_job)
            # Now, we can send out the new prev hash, since all jobs are
            # invalidated. Any further submits for the invalidated jobs will be
            # rejected
            self._send_msg(prev_hash_msg)

        # We can now broadcast future jobs to all channels for the upcoming block
        for channel in self._mining_channel_registry.channels:
            future_new_job_msg = self.__build_new_job_msg(channel, is_future_job=True)
            self._send_msg(future_new_job_msg)

    def __build_set_new_prev_hash_msg(self, channel_id, future_job_id):
        return SetNewPrevHash(
            channel_id=channel_id,
            job_id=future_job_id,
            prev_hash=self.prev_hash if self.prev_hash else 0,
            min_ntime=int(time.time()),  # self.env.now,
            nbits=0,  # TODO: None?
        )

    @staticmethod
    def __build_new_job_msg(mining_channel: PoolMiningChannel, is_future_job: bool):
        """Builds NewMiningJob or NewExtendedMiningJob depending on channel type.

        The method also builds the actual job and registers it as 'future' job within
        the channel if requested.

        :param channel: determines the channel and thus message type
        :param is_future_job: when true, the job won't be considered for the current prev
         hash known to the downstream node but for any future prev hash that explicitly
         selects it
        :return New{Extended}MiningJob
        """
        version = 1
        merkle_root = bytes(random.getrandbits(8) for _ in range(32))

        new_job = mining_channel.session.new_mining_job(version, merkle_root)
        if is_future_job:
            mining_channel.add_future_job(new_job)

        # Compose the protocol message based on actual channel type
        if isinstance(mining_channel.cfg, OpenStandardMiningChannel):
            msg = NewMiningJob(
                channel_id=mining_channel.id,
                job_id=new_job.uid,
                future_job=is_future_job,
                version=version,
                merkle_root=merkle_root,
            )
        elif isinstance(mining_channel.cfg, OpenExtendedMiningChannel):
            msg = NewExtendedMiningJob(
                channel_id=mining_channel.id,
                job_id=new_job.uid,
                future_job=is_future_job,
                version=version,
                version_rolling_allowed=True,  # TODO
                merkle_path=MerklePath(),
                cb_prefix=CoinBasePrefix(),
                cb_suffix=CoinBaseSuffix(),
            )
        else:
            assert False, "Unsupported channel type: {}".format(
                mining_channel.cfg.channel_type
            )

        return msg

    def __emit_channel_msg_on_bus(self, msg: ChannelMessage):
        """Helper method for reporting a channel oriented message on the debugging bus."""
        self._emit_protocol_msg_on_bus("Channel ID: {}".format(msg.channel_id), msg)
