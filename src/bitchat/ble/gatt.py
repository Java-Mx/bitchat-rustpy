"""GATT discovery and validation for BitChat services and characteristics."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.exceptions import BLEGATTError
from bitchat.protocol.constants import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
)

if TYPE_CHECKING:
    from bleak.backends.characteristic import BleakGATTCharacteristic

logger = logging.getLogger(__name__)


def _normalize_uuid(uuid_str: str) -> str:
    """Normalize UUID for hyphen- and case-insensitive comparison."""
    return str(uuid_str).strip().lower().replace("-", "")


class GATTManager:
    """Discovers and validates BitChat GATT service and characteristic layout."""

    def __init__(
        self,
        service_uuid: str = BITCHAT_SERVICE_UUID,
        characteristic_uuid: str = BITCHAT_CHARACTERISTIC_UUID,
    ) -> None:
        self.service_uuid = service_uuid.lower()
        self.characteristic_uuid = characteristic_uuid.lower()
        self._norm_service_uuid = _normalize_uuid(service_uuid)
        self._norm_char_uuid = _normalize_uuid(characteristic_uuid)
        self.last_write_mode: str = "write-without-response"

    async def discover(self, client: Any) -> Any:
        """Discover and validate the BitChat service and characteristic."""
        if not getattr(client, "is_connected", False):
            raise BLEGATTError(
                f"Cannot discover GATT on disconnected client {client.address}"
            )

        try:
            services = getattr(client, "services", None)
            if not services and hasattr(client, "get_services"):
                services = await client.get_services()
        except Exception as e:
            raise BLEGATTError(
                f"Failed to retrieve GATT services from {client.address}: {e}"
            ) from e

        if services is None:
            raise BLEGATTError(
                f"No GATT services discovered on client {client.address}"
            )

        # 1. Locate BitChat Service
        service_found = False
        target_char: BleakGATTCharacteristic | None = None

        for service in services:
            if _normalize_uuid(service.uuid) == self._norm_service_uuid:
                service_found = True
                for char in service.characteristics:
                    if _normalize_uuid(char.uuid) == self._norm_char_uuid:
                        target_char = char
                        break
                break

        # Fallback: search all characteristics if service nesting is flattened
        if target_char is None and services:
            for service in services:
                for char in service.characteristics:
                    if _normalize_uuid(char.uuid) == self._norm_char_uuid:
                        target_char = char
                        service_found = True
                        break
                if target_char is not None:
                    break

        if not service_found:
            raise BLEGATTError(
                f"BitChat service {self.service_uuid} not found on {client.address}"
            )

        if target_char is None:
            raise BLEGATTError(
                f"BitChat characteristic {self.characteristic_uuid} not found "
                f"on {client.address}"
            )

        # 2. Validate Characteristic Properties (strict when properties are reported)
        raw_props = getattr(target_char, "properties", None)
        props = [str(p).strip().lower() for p in (raw_props or [])]
        if props:
            if HAS_NATIVE_CORE and hasattr(
                _core, "validate_ble_gatt_characteristic_raw"
            ):
                try:
                    self.last_write_mode = str(
                        _core.validate_ble_gatt_characteristic_raw(
                            str(target_char.uuid),
                            props,
                            self.characteristic_uuid,
                        )
                    )
                except ValueError as e:
                    raise BLEGATTError(str(e)) from e
            else:
                can_write_no_resp = any(
                    p in props
                    for p in ("write-without-response", "write without response")
                )
                can_write = can_write_no_resp or ("write" in props)
                can_notify = any(p in props for p in ("notify", "indicate"))
                if not can_notify:
                    raise BLEGATTError(
                        f"Characteristic {target_char.uuid} missing required notify "
                        f"property (found: {props})"
                    )
                if not can_write:
                    raise BLEGATTError(
                        f"Characteristic {target_char.uuid} missing required write "
                        f"property (found: {props})"
                    )
                self.last_write_mode = (
                    "write-without-response"
                    if can_write_no_resp
                    else "write-with-response"
                )
        else:
            self.last_write_mode = "write-without-response"

        logger.debug(
            "Resolved BitChat GATT characteristic %s on %s (properties=%s, mode=%s)",
            target_char.uuid,
            client.address,
            props,
            self.last_write_mode,
        )
        return target_char
