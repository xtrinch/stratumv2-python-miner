"""Generic pool module"""
import base64
import hashlib
import socket

import numpy as np
import simpy
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
import random

import primitives.coins as coins
from primitives.messages import *
from primitives.protocol import ConnectionProcessor
from primitives.types import DownstreamConnectionFlags, UpstreamConnectionFlags


class MiningJob:
    """This class allows the simulation to track per job difficulty target for
    correct accounting"""

    def __init__(
        self, uid: int, diff_target: coins.Target, version: int, merkle_root: bytes
    ):
        """
        :param uid:
        :param diff_target: difficulty target
        """
        self.uid = uid
        self.diff_target = diff_target
        self.version = version
        self.merkle_root = merkle_root
        self.is_cancelled = False
        # mining start as unix timestamp
        self.started_at = None
        # mining end as unix timestamp
        self.finished_at = None

    def _format(self, content):
        return "{}({})".format(type(self).__name__, content)

    def __str__(self):
        return self._format(
            "uid={}, diff_target={}".format(
                self.uid,
                self.diff_target,
            )
        )


class MiningJobRegistry:
    """Registry of jobs that have been assigned for mining.

    The registry intentionally doesn't remove any jobs from the simulation so that we
    can explicitly account for 'stale' hashrate. When this requirement is not needed,
    the retire_all_jobs() can be adjusted accordingly"""

    def __init__(self):
        # Tracking minimum valid job ID
        self.next_job_uid = 0
        # Registered jobs based on their uid
        self.jobs = dict()
        # Invalidated jobs just for accounting reasons
        self.invalid_jobs = dict()

    def new_mining_job(
        self, diff_target: coins.Target, version: int, merkle_root: bytes, job_id=None
    ):
        """Prepares new mining job and registers it internally.

        :param diff_target: difficulty target of the job to be constructed
        :param job_id: optional identifier of a job. If not specified, the registry
        chooses its own identifier.
        :return new mining job or None if job with the specified ID already exists
        """
        if job_id is None:
            job_id = self.__next_job_uid()
        if job_id not in self.jobs:
            new_job = MiningJob(
                uid=job_id,
                diff_target=diff_target,
                version=version,
                merkle_root=merkle_root,
            )
            self.jobs[new_job.uid] = new_job
        else:
            new_job = None
        return new_job

    def get_job(self, job_uid):
        """
        :param job_uid: job_uid to look for
        :return: Returns the job or None
        """
        return self.jobs.get(job_uid)

    def get_job_diff_target(self, job_uid):
        return self.jobs[job_uid].diff_target

    def get_invalid_job_diff_target(self, job_uid):
        return self.invalid_jobs[job_uid].diff_target

    def contains(self, job_uid):
        """Job ID presence check
        :return True when when such Job ID exists in the registry (it may still not
        be valid)"""
        return job_uid in self.jobs

    def contains_invalid(self, job_uid):
        """Check the invalidated job registry
        :return True when when such Job ID exists in the registry (it may still not
        be valid)"""
        return job_uid in self.invalid_jobs

    def retire_all_jobs(self):
        """Make all jobs invalid, while storing their copy for accounting reasons"""
        self.invalid_jobs.update(self.jobs)
        self.jobs = dict()

    def add_job(self, job: MiningJob):
        """
        Appends a job with an assigned ID into the registry
        :param job:
        :return:
        """
        assert (
            self.get_job(job.uid) is None
        ), "Job {} already exists in the registry".format(job)
        self.jobs[job.uid] = job

    def __next_job_uid(self):
        """Initializes a new job ID for this session."""
        curr_job_uid = self.next_job_uid
        self.next_job_uid += 1

        return curr_job_uid


class MiningSession:
    """Represents a mining session that can adjust its difficulty target"""

    min_factor = 0.25
    max_factor = 4

    def __init__(
        self,
        name: str,
        bus: EventBus,
        owner,
        diff_target: coins.Target,
        enable_vardiff,
        vardiff_time_window=None,
        vardiff_desired_submits_per_sec=None,
        on_vardiff_change=None,
    ):
        """ """
        self.name = name
        self.bus = bus
        self.owner = owner
        self.curr_diff_target = diff_target
        self.enable_vardiff = enable_vardiff
        self.meter = None
        self.vardiff_process = None
        self.vardiff_time_window_size = vardiff_time_window
        self.vardiff_desired_submits_per_sec = vardiff_desired_submits_per_sec
        self.on_vardiff_change = on_vardiff_change

        self.job_registry = MiningJobRegistry()
        self.prev_hash = None
        self.min_ntime = None
        self.nbits = None

    @property
    def curr_target(self):
        """Derives target from current difficulty on the session"""
        return self.curr_diff_target

    def set_target(self, target: coins.Target):
        self.curr_diff_target = target

    def set_prev_hash(self, msg: SetNewPrevHash):
        self.prev_hash = msg.prev_hash
        self.min_ntime = msg.min_ntime
        self.nbits = msg.nbits

    def new_mining_job(self, version: int, merkle_root: bytes, job_uid=None):
        """Generates a new job using current session's target"""
        return self.job_registry.new_mining_job(
            self.curr_diff_target, version, merkle_root, job_uid
        )

    def run(self):
        """Explicit activation starts any simulation processes associated with the session"""
        self.meter = HashrateMeter()
        # if self.enable_vardiff:
        #     self.vardiff_process = self.env.process(self.__vardiff_loop())

    def account_diff_shares(self, diff: int):
        assert (
            self.meter is not None
        ), "BUG: session not running yet, cannot account shares"
        self.meter.measure(diff)

    def terminate(self):
        """Complete shutdown of the session"""
        self.meter.terminate()
        if self.enable_vardiff:
            self.vardiff_process.interrupt()

    def __vardiff_loop(self):
        while True:
            try:
                submits_per_sec = self.meter.get_submit_per_secs()
                if submits_per_sec is None:
                    # no accepted shares, we will halve the diff
                    factor = 0.5
                else:
                    factor = submits_per_sec / self.vardiff_desired_submits_per_sec
                if factor < self.min_factor:
                    factor = self.min_factor
                elif factor > self.max_factor:
                    factor = self.max_factor
                self.curr_diff_target.div_by_factor(factor)
                self.__emit_aux_msg_on_bus(
                    "DIFF_UPDATE(target={})".format(self.curr_diff_target)
                ),
                self.on_vardiff_change(self)
                # yield self.env.timeout(self.vardiff_time_window_size)
            except simpy.Interrupt:
                break

    def __emit_aux_msg_on_bus(self, msg):
        self.bus.emit(self.name, None, self.owner, msg)


class MiningChannel:
    def __init__(self, cfg, conn_uid, channel_id):
        """
        :param cfg: configuration is represented by the full OpenStandardMiningChannel or
        OpenStandardMiningChannelSuccess message depending on which end of the channel we are on
        :param conn_uid: backlink to the connection this channel is on
        :param channel_id: unique identifier for the channel
        """
        self.cfg = cfg
        self.conn_uid = conn_uid
        self.id = channel_id
        self.channel_id = channel_id

    def set_id(self, channel_id):
        self.id = channel_id


class PoolMiningChannel(MiningChannel):
    """This mining channel contains mining session and future job.

    Currently, the channel holds only 1 future job.
    """

    def __init__(self, session, *args, **kwargs):
        """
        :param session: optional mining session process (TODO: review if this is the right place)
        """
        self.future_job = None
        self.session = session
        super().__init__(*args, **kwargs)

    def terminate(self):
        self.session.terminate()

    def set_session(self, session):
        self.session = session

    def take_future_job(self):
        """Takes future job from the channel."""
        assert (
            self.future_job is not None
        ), "BUG: Attempt to take a future job from channel: {}".format(self.id)
        future_job = self.future_job
        self.future_job = None
        return future_job

    def add_future_job(self, job):
        """Stores future job ready for mining should a new block be found"""
        assert (
            self.future_job is None
        ), "BUG: Attempt to overwrite an existing future job: {}".format(self.id)
        self.future_job = job


class ConnectionConfig:
    """Stratum V2 connection configuration.

    For now, it is sufficient to record the SetupConnection to have full connection configuration available.
    """

    def __init__(self, msg: SetupConnection):
        self.setup_msg = msg

    @property
    def requires_version_rolling(self):
        return (
            DownstreamConnectionFlags.REQUIRES_VERSION_ROLLING in self.setup_msg.flags
        )


class ChannelRegistry:
    """Keeps track of channels on individual connection"""

    def __init__(self, conn_uid):
        self.conn_uid = conn_uid
        self.channels = []

    def append(self, channel):
        """Simplify registering new channels"""
        new_channel_id = len(self.channels)
        channel.set_id(new_channel_id)
        self.channels.append(channel)

    def get_channel(self, channel_id):
        if channel_id < len(self.channels):
            return self.channels[channel_id]
        else:
            return None
