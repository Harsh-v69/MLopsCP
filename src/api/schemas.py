"""Pydantic request/response models for the Phase 4 inference API.

Field set and bounds locked in docs/phase4_api_spec.md before this file was
written. Validation here is the only gate in front of the model — see the
spec's "Error behavior" section for why an out-of-schema request must never
reach the pipeline.
"""
from typing import List, Literal

from pydantic import BaseModel, Field, confloat, conint

KNOWN_PROTOCOLS = Literal["tcp", "udp", "icmp"]
KNOWN_FLAGS = Literal["SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "S3", "RSTOS0", "OTH"]

NonNegInt = conint(ge=0)
BinaryInt = conint(ge=0, le=1)
UnitRate = confloat(ge=0.0, le=1.0)


class ConnectionRecord(BaseModel):
    duration: NonNegInt
    protocol_type: KNOWN_PROTOCOLS
    service: str = Field(..., min_length=1)
    flag: KNOWN_FLAGS
    src_bytes: NonNegInt
    dst_bytes: NonNegInt
    land: BinaryInt
    wrong_fragment: NonNegInt
    urgent: NonNegInt
    hot: NonNegInt
    num_failed_logins: NonNegInt
    logged_in: BinaryInt
    num_compromised: NonNegInt
    root_shell: BinaryInt
    su_attempted: BinaryInt
    num_root: NonNegInt
    num_file_creations: NonNegInt
    num_shells: NonNegInt
    num_access_files: NonNegInt
    num_outbound_cmds: NonNegInt
    is_host_login: BinaryInt
    is_guest_login: BinaryInt
    count: NonNegInt
    srv_count: NonNegInt
    serror_rate: UnitRate
    srv_serror_rate: UnitRate
    rerror_rate: UnitRate
    srv_rerror_rate: UnitRate
    same_srv_rate: UnitRate
    diff_srv_rate: UnitRate
    srv_diff_host_rate: UnitRate
    dst_host_count: NonNegInt
    dst_host_srv_count: NonNegInt
    dst_host_same_srv_rate: UnitRate
    dst_host_diff_srv_rate: UnitRate
    dst_host_same_src_port_rate: UnitRate
    dst_host_srv_diff_host_rate: UnitRate
    dst_host_serror_rate: UnitRate
    dst_host_srv_serror_rate: UnitRate
    dst_host_rerror_rate: UnitRate
    dst_host_srv_rerror_rate: UnitRate


class PredictRequest(BaseModel):
    records: List[ConnectionRecord] = Field(..., min_length=1)


class Prediction(BaseModel):
    label: Literal["normal", "attack"]
    attack_probability: float


class PredictResponse(BaseModel):
    predictions: List[Prediction]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model_loaded: bool
    model_source: str
