"""
Hardware Information Collector for GIAM-SAT Agent v1.9.0
Collects motherboard, BIOS, disk, RAM, GPU, monitor, installed software via WMI
Sends to server on first install / after reboot
"""

import json
import platform
import os
import subprocess
import re
from datetime import datetime


# EDID 3-letter manufacturer code -> friendly brand name
MONITOR_MFR_MAP = {
    "DEL": "Dell", "SAM": "Samsung", "SEC": "Samsung", "ACI": "Acer",
    "ACR": "Acer", "AOC": "AOC", "HPN": "HP", "HWP": "HP", "LEN": "Lenovo",
    "LGE": "LG", "GSM": "LG", "PHL": "Philips", "VSC": "ViewSonic",
    "SNY": "Sony", "AUS": "ASUS", "BNQ": "BenQ", "NEC": "NEC", "EIZ": "Eizo",
    "IVM": "Iiyama", "MSI": "MSI", "GWD": "Gigabyte", "HSD": "Hannspree",
    "AUO": "AU Optronics", "CMN": "Chimei Innolux", "BOE": "BOE",
    "AIC": "AG Neovo", "VES": "Vestel", "TCL": "TCL",
}


class HWCollector:
    def __init__(self):
        self.info = {}

    def collect(self):
        """Collect all hardware info and return as dict."""
        self.info = {
            "type": "machine_config",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "os": self._get_os_info(),
            "motherboard": self._get_motherboard(),
            "bios": self._get_bios(),
            "cpu": self._get_cpu(),
            "ram": self._get_ram(),
            "disks": self._get_disks(),
            "gpu": self._get_gpu(),
            "monitors": self._get_monitors(),
            "installed_software": self._get_installed_software(),
            "printers": self._get_printers(),
        }
        return self.info

    def _run_powershell(self, script):
        """Run a PowerShell script and return output."""
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command", script],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return proc.stdout.strip()
        except Exception:
            return ""

    def _get_os_info(self):
        """Get OS information."""
        try:
            return {
                "name": platform.system(),
                "version": platform.version(),
                "release": platform.release(),
                "build": platform.win32_ver()[1] if hasattr(platform, 'win32_ver') else ""
            }
        except Exception:
            return {"name": "Windows", "version": "Unknown"}

    def _get_motherboard(self):
        """Get motherboard info via WMI."""
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, Version, SerialNumber | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    data = data[0] if data else {}
                return {
                    "manufacturer": data.get("Manufacturer", "").strip(),
                    "product": data.get("Product", "").strip(),
                    "version": data.get("Version", "").strip(),
                    "serial": data.get("SerialNumber", "").strip()
                }
        except Exception:
            pass
        return {"manufacturer": "", "product": "", "version": "", "serial": ""}

    def _get_bios(self):
        """Get BIOS info via WMI."""
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_BIOS | Select-Object Manufacturer, Name, Version, SerialNumber, ReleaseDate | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    data = data[0] if data else {}
                release_date = data.get("ReleaseDate", "")
                if release_date and len(release_date) >= 8:
                    release_date = f"{release_date[0:4]}-{release_date[4:6]}-{release_date[6:8]}"
                return {
                    "manufacturer": data.get("Manufacturer", "").strip(),
                    "name": data.get("Name", "").strip(),
                    "version": data.get("Version", "").strip(),
                    "serial": data.get("SerialNumber", "").strip(),
                    "release_date": release_date
                }
        except Exception:
            pass
        return {"manufacturer": "", "name": "", "version": "", "serial": "", "release_date": ""}

    def _get_cpu(self):
        """Get CPU info."""
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_Processor | Select-Object Name, Manufacturer, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    data = data[0] if data else {}
                return {
                    "name": data.get("Name", "").strip(),
                    "manufacturer": data.get("Manufacturer", "").strip(),
                    "max_clock_speed_mhz": str(data.get("MaxClockSpeed", "")),
                    "cores": str(data.get("NumberOfCores", "")),
                    "logical_processors": str(data.get("NumberOfLogicalProcessors", ""))
                }
        except Exception:
            pass
        return {"name": "", "manufacturer": "", "max_clock_speed_mhz": "", "cores": "", "logical_processors": ""}

    def _get_ram(self):
        """Get RAM info - individual sticks with form factor and memory type."""
        # Form factor mapping
        FF_MAP = {
            0: "Unknown", 1: "Other", 2: "SIP", 3: "DIP", 4: "ZIP",
            5: "SOJ", 6: "Proprietary", 7: "SIMM", 8: "DIMM", 9: "TSOP",
            10: "PGA", 11: "RIMM", 12: "SODIMM", 13: "SRIMM",
            14: "SMD", 15: "SSMP", 16: "QFP", 17: "TQFP", 18: "SOIC",
            19: "LCC", 20: "PLCC", 21: "BGA", 22: "FPBGA", 23: "LGA",
            24: "FB-DIMM"
        }
        # Memory type mapping (SMBIOS)
        MT_MAP = {
            0: "Unknown", 1: "Other", 2: "DRAM", 3: "Synchronous DRAM",
            4: "Cache DRAM", 5: "EDO", 6: "EDRAM", 7: "VRAM", 8: "SRAM",
            9: "RAM", 10: "ROM", 11: "Flash", 12: "EEPROM", 13: "FEPROM",
            14: "EPROM", 15: "CDRAM", 16: "3DRAM", 17: "SDRAM",
            18: "SGRAM", 19: "RDRAM", 20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM",
            24: "DDR3", 25: "FBD2", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2",
            29: "LPDDR3", 30: "LPDDR4", 31: "Logical non-volatile device",
            32: "HBM", 33: "HBM2", 34: "DDR5", 35: "LPDDR5"
        }
        ram_sticks = []
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed, PartNumber, FormFactor, MemoryType, SMBIOSMemoryType, ConfiguredClockSpeed | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for stick in items:
                    capacity_bytes = int(stick.get("Capacity", 0) or 0)
                    capacity_gb = capacity_bytes / (1024**3)
                    ff_raw = stick.get("FormFactor", 0) or 0
                    ff = FF_MAP.get(ff_raw, f"Unknown({ff_raw})")
                    smbios_mt = stick.get("SMBIOSMemoryType", 0) or 0
                    mem_type = MT_MAP.get(smbios_mt, MT_MAP.get(stick.get("MemoryType", 0) or 0, "Unknown"))
                    speed = str(stick.get("Speed", "") or "")
                    configured_speed = str(stick.get("ConfiguredClockSpeed", "") or "")
                    ram_sticks.append({
                        "manufacturer": stick.get("Manufacturer", "").strip(),
                        "capacity_gb": round(capacity_gb, 1),
                        "speed_mhz": speed,
                        "configured_speed_mhz": configured_speed,
                        "memory_type": mem_type,
                        "form_factor": ff,
                        "part_number": stick.get("PartNumber", "").strip()
                    })
        except Exception:
            pass

        # Total RAM
        total_ram = 0
        try:
            output2 = self._run_powershell(
                "Get-WmiObject Win32_ComputerSystem | Select-Object TotalPhysicalMemory | ConvertTo-Json"
            )
            if output2:
                data = json.loads(output2)
                total_bytes = int(data.get("TotalPhysicalMemory", 0) or 0)
                total_ram = round(total_bytes / (1024**3), 1)
        except Exception:
            pass

        return {
            "total_gb": total_ram,
            "sticks": ram_sticks
        }

    def _get_disks(self):
        """Get disk/drive info."""
        disks = []
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_DiskDrive | Select-Object Model, Manufacturer, Size, InterfaceType, MediaType | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for disk in items:
                    size_bytes = int(disk.get("Size", 0) or 0)
                    size_gb = round(size_bytes / (1024**3), 1) if size_bytes > 0 else 0
                    disks.append({
                        "model": disk.get("Model", "").strip(),
                        "manufacturer": disk.get("Manufacturer", "").strip(),
                        "size_gb": size_gb,
                        "interface": disk.get("InterfaceType", "").strip(),
                        "media_type": disk.get("MediaType", "").strip()
                    })
        except Exception:
            pass
        return disks

    def _get_gpu(self):
        """Get GPU info."""
        gpus = []
        try:
            output = self._run_powershell(
                "Get-WmiObject Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription, VideoProcessor | ConvertTo-Json"
            )
            if output:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for gpu in items:
                    ram_bytes = int(gpu.get("AdapterRAM", 0) or 0)
                    ram_gb = round(ram_bytes / (1024**3), 2) if ram_bytes > 0 else 0
                    gpus.append({
                        "name": gpu.get("Name", "").strip(),
                        "ram_gb": ram_gb,
                        "driver_version": gpu.get("DriverVersion", "").strip(),
                        "video_processor": gpu.get("VideoProcessor", "").strip()
                    })
        except Exception:
            pass
        return gpus

    def _get_monitors(self):
        """Get monitor info via WMI EDID (WmiMonitorID) with PnPEntity fallback."""
        monitors = []
        # Primary: WmiMonitorID (root\wmi) returns the real EDID model/manufacturer
        try:
            script = r"""
$out = @()
$mons = Get-WmiObject -Namespace root\wmi -Class WmiMonitorID -ErrorAction SilentlyContinue
foreach ($m in $mons) {
    $name = ''
    $mfr = ''
    if ($m.UserFriendlyName) { $name = -join ($m.UserFriendlyName | ForEach-Object { if ($_ -gt 0) { [char]$_ } }) }
    if ($m.ManufacturerName) { $mfr = -join ($m.ManufacturerName | ForEach-Object { if ($_ -gt 0) { [char]$_ } }) }
    if ($name -or $mfr) {
        $out += [PSCustomObject]@{ Name = $name.Trim(); Manufacturer = $mfr.Trim() }
    }
}
$out | ConvertTo-Json
"""
            output = self._run_powershell(script)
            if output and output not in ("", "null", "[]"):
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for mon in items:
                    name = (mon.get("Name") or "").strip()
                    mfr_code = (mon.get("Manufacturer") or "").strip()
                    monitors.append({
                        "name": name,
                        "manufacturer": MONITOR_MFR_MAP.get(mfr_code.upper(), mfr_code or "Unknown"),
                        "type": "Monitor",
                        "resolution": "",
                    })
        except Exception:
            pass

        # Fallback: Win32_PnPEntity (skip useless generic names)
        if not monitors:
            try:
                output2 = self._run_powershell(
                    "Get-WmiObject Win32_PnPEntity | Where-Object {$_.PNPClass -eq 'Monitor'} | Select-Object Name, DeviceID, Manufacturer | ConvertTo-Json"
                )
                if output2 and output2 != "null" and output2 != "":
                    data2 = json.loads(output2)
                    items = data2 if isinstance(data2, list) else [data2]
                    generic = {"generic pnp monitor", "generic non-pnp monitor", "default monitor"}
                    for mon in items:
                        name = (mon.get("Name") or "").strip()
                        if not name or name.lower() in generic:
                            continue
                        monitors.append({
                            "name": name,
                            "manufacturer": (mon.get("Manufacturer") or "").strip() or "Unknown",
                            "type": "Monitor",
                            "resolution": ""
                        })
            except Exception:
                pass

        return monitors

    def _get_installed_software(self):
        """Get list of installed software from registry (faster than Win32_Product which triggers reconfigure)."""
        software_list = []
        try:
            # Use registry-based approach (faster, no reconfigure)
            script = """
$software = @()
$paths = @(
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
    "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
)
foreach ($path in $paths) {
    if (Test-Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall") {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' }
            foreach ($item in $items) {
                $name = $item.DisplayName.Trim()
                if ($name -eq '' -or $name -like '*Update for*' -or $name -like '*Security Update*' -or $name -like '*Hotfix*') { continue }
                $software += [PSCustomObject]@{
                    Name = $name
                    Version = if ($item.DisplayVersion) { $item.DisplayVersion.ToString().Trim() } else { '' }
                    Publisher = if ($item.Publisher) { $item.Publisher.ToString().Trim() } else { '' }
                    InstallDate = if ($item.InstallDate) { $item.InstallDate.ToString().Trim() } else { '' }
                }
            }
        } catch {}
        break  # First successful registry path is enough
    }
}
$software | Sort-Object Name -Unique | Select-Object -First 200 | ConvertTo-Json
"""
            output = self._run_powershell(script)
            if output:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for sw in items:
                    software_list.append({
                        "name": sw.get("Name", "").strip(),
                        "version": sw.get("Version", "").strip(),
                        "publisher": sw.get("Publisher", "").strip(),
                        "install_date": sw.get("InstallDate", "").strip()
                    })
        except Exception:
            pass
        return software_list

    def _get_printers(self):
        """Get installed printers (USB + network) via WMI Win32_Printer.
        PortName 'USBxxx' => printer plugged directly into this machine (USB);
        others (IP_ / network) => network printer. Used for IT asset tracking."""
        printers = []
        try:
            script = (
                "Get-WmiObject Win32_Printer | Select-Object Name, DriverName, "
                "PortName, Network, Local, Default | ConvertTo-Json"
            )
            output = self._run_powershell(script)
            if output:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for p in items:
                    port = (p.get("PortName") or "").strip()
                    is_usb = port.lower().startswith("usb")
                    printers.append({
                        "name": (p.get("Name") or "").strip(),
                        "driver": (p.get("DriverName") or "").strip(),
                        "port": port,
                        "connection": "usb" if is_usb else "network",
                        "is_default": bool(p.get("Default")),
                    })
        except Exception:
            pass
        return printers

    def to_json(self):
        """Return collected data as JSON string."""
        return json.dumps(self.collect(), ensure_ascii=False, default=str)


if __name__ == "__main__":
    collector = HWCollector()
    info = collector.collect()
    print(json.dumps(info, indent=2, ensure_ascii=False, default=str))