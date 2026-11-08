# SPDX-License-Identifier: GPL-3.0-or-later
"""Model registry: SIM_MODEL value -> Model class."""

from .apc_ups import ApcUps
from .ups_rfc1628 import UpsRfc1628
from .raritan_pdu import RaritanPdu
from .liebert_crac import LiebertCrac
from .switch import Switch

MODELS = {
    "apc-ups": ApcUps,
    "ups-rfc1628": UpsRfc1628,
    "raritan-pdu": RaritanPdu,
    "liebert-crac": LiebertCrac,
    "switch": Switch,
}


def get_model(name):
    try:
        return MODELS[name]
    except KeyError:
        raise SystemExit("unknown SIM_MODEL %r (choose from %s)" % (name, ", ".join(MODELS)))
