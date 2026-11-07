from .base import Adapter, AdapterError, Capabilities, FetchResult
from .simulator import Simulator
from .zk_tcp import ZKTcp


def adapter_for(device, config, store, cancelled=None):
    if device.get("adapter") == "simulator" and config.development and config.simulator_file:
        return Simulator(device, config.simulator_file, store)
    if device.get("adapter") == "zk-tcp":
        return ZKTcp(device, config, store, cancelled=cancelled)
    raise AdapterError("UNSUPPORTED")
