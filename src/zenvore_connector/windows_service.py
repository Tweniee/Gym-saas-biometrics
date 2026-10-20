"""Frozen pywin32 Windows service entry point; run under LocalSystem."""
import os
from pathlib import Path
import servicemanager
import win32event
import win32service
import win32serviceutil
from zenvore_connector.config import Config, default_home
from zenvore_connector.main import InstanceLock, build, configure_logging


class ConnectorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ZenvoreBiometricConnector"
    _svc_display_name_ = "Zenvore Biometric Connector"
    _svc_description_ = "Connects assigned biometric devices to Zenvore using outbound HTTPS."

    def __init__(self, args):
        super().__init__(args)
        self.stopping = win32event.CreateEvent(None, 0, 0, None)
        self.runtime = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=60000)
        win32event.SetEvent(self.stopping)
        if self.runtime:
            self.runtime.stop.set()

    def SvcDoRun(self):
        config = Config.load(default_home() / "config.json")
        handler = configure_logging(config.state_dir)
        lock = InstanceLock(config.state_dir)
        self.runtime = build(config)
        try:
            self.runtime.start()
            win32event.WaitForSingleObject(self.stopping, win32event.INFINITE)
            self.runtime.shutdown()
        finally:
            self.runtime.store.close()
            lock.close()
            handler.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ConnectorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(ConnectorService)
