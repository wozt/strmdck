from __future__ import annotations

import binascii
import json
import logging
import os
import shutil
import time
from datetime import datetime
from enum import Enum
from typing import Dict
from zoneinfo import ZoneInfo

from construct import (
    Adapter,
    Byte,
    Bytes,
    BytesInteger,
    ByteSwapped,
    Const,
    CString,
    ExprAdapter,
    GreedyBytes,
    Int32ub,
    Padded,
    Struct,
    Switch,
    this,
)
from deepdiff import DeepDiff
from dotenv import load_dotenv

from ..device import ButtonAction, DeckDevice
from ..utils import compress_folder

logger = logging.getLogger(__name__)
# Separate logger for invalid-byte correction so it can be filtered independently.
logger_fix = logging.getLogger(__name__ + ".fix")

# Set to 1 to force console logging without environment variables.
FORCE_ULANZI_LOGGING = 0
# Set to 1 to force detailed correction logs even if general logging is off.
FORCE_ULANZI_FIX_LOGGING = 1
# Padding config for ZIP invalid-byte mitigation.
PADDING_SIZE = 64
PADDING_ATTEMPTS = 20

def _configure_logging_from_env():
    """Enable console logging when env flags or FORCE_ULANZI_LOGGING are set."""
    debug_flag = os.getenv('ULANZI_DEBUG')
    level_name = os.getenv('ULANZI_LOG_LEVEL')

    if not FORCE_ULANZI_LOGGING and not debug_flag and not level_name:
        return

    level = logging.DEBUG if debug_flag or FORCE_ULANZI_LOGGING else getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    logger.setLevel(level)
    # Use the same level for the fix logger unless explicitly forced.
    logger_fix.setLevel(logging.DEBUG if FORCE_ULANZI_FIX_LOGGING else level)

load_dotenv()
_configure_logging_from_env()

timezone = ZoneInfo(os.getenv('TIMEZONE', 'America/New_York'))


class SmallWindowMode(Enum):
    STATS = 0
    CLOCK = 1
    BACKGROUND = 2


class CommandProtocol(Enum):
    OUT_SET_BUTTONS = 0x0001
    OUT_PARTIALLY_UPDATE_BUTTONS = 0x000d

    OUT_SET_SMALL_WINDOW_DATA = 0x0006
    OUT_SET_BRIGHTNESS = 0x000a
    OUT_SET_LABEL_STYLE = 0x000b

    IN_BUTTON = 0x0101
    IN_DEVICE_INFO = 0x0303


class InvalidZipContent(Exception):
    """Raised when button ZIP still contains invalid bytes after mitigation."""


class LengthAdapter(Adapter):
    def _encode(self, obj, context, path):
        return obj if obj is not None else len(context.data)

    def _decode(self, obj, context, path):
        return obj


PacketStruct = Struct(
    Const(b'\x7c\x7c'),
    'command_protocol' / BytesInteger(2),
    'length' / LengthAdapter(ByteSwapped(Int32ub)),
    'data' / Padded(1024 - 8, GreedyBytes),
)


ButtonPressedStruct = Struct(
    'state' / Byte,
    'index' / Byte,
    Const(b'\x01'),
    'pressed' / ExprAdapter(Byte, lambda obj, ctx: obj == 0x1, lambda obj, ctx: 0x1 if obj else 0x0),
)

IncomingStruct = Struct(
    Bytes(2),  # b'\x7c\x7c'
    'command_protocol' / BytesInteger(2),
    'length' / ByteSwapped(Int32ub),
    'data' / Switch(this.command_protocol, {0x0101: ButtonPressedStruct, 0x0303: CString('ascii')}),
)


class UlanziD200Device(DeckDevice):
    USB_VENDOR_ID = 0x2207
    USB_PRODUCT_ID = 0x0019

    BUTTON_COUNT = 13
    BUTTON_ROWS = 3
    BUTTON_COLS = 5

    ICON_WIDTH = 196
    ICON_HEIGHT = 196

    DECK_NAME = 'Ulanzi Stream Controller D200'

    def __init__(self, hid_device):
        super().__init__(hid_device)
        self._small_window_mode = SmallWindowMode.CLOCK

    def keep_alive(self):
        self.set_small_window_data({})

    def set_brightness(self, brightness: int, force=False):
        if not force and brightness == self._brightness:
            return

        self._brightness = brightness
        packet = PacketStruct.build(dict(
            command_protocol=CommandProtocol.OUT_SET_BRIGHTNESS.value,
            length=None,
            data=str(brightness).encode('utf-8'),
        ))

        self._write_packet(packet)

    def set_label_style(self, label_style: Dict, force=False):
        if not force and not DeepDiff(self._label_style, label_style):
            return False

        label_style.setdefault('align', 'bottom')
        label_style.setdefault('color', 'FFFFFF')
        label_style.setdefault('font_name', 'Roboto')
        label_style.setdefault('show_title', True)
        label_style.setdefault('size', 10)
        label_style.setdefault('weight', 80)
        self._label_style = label_style

        style = {
            'Align': label_style['align'],
            'Color': int(label_style['color'], 16),
            'FontName': label_style['font_name'],
            'ShowTitle': bool(label_style['show_title']),
            'Size': label_style['size'],
            'Weight': label_style['weight'],
        }

        packet = PacketStruct.build(dict(
            command_protocol=CommandProtocol.OUT_SET_LABEL_STYLE.value,
            length=None,
            data=bytearray(json.dumps(style).encode('utf-8')),
        ))

        self._write_packet(packet)
        print('set_label_style')

    def set_small_window_data(self, data: Dict, force=False):
        if not force and not DeepDiff(self._small_window_data, data):
            return False

        data.setdefault('time', datetime.now(timezone).strftime('%H:%M:%S'))
        data.setdefault('mode', self._small_window_mode)
        data.setdefault('cpu', 0)
        data.setdefault('mem', 0)
        data.setdefault('gpu', 0)

        self._small_window_data = data

        # "1|9|64|16:23:04|0"  cpu: "9"  mem: "64"  time: "16:23:04"  GPU: "0"
        data = f'{data["mode"].value}|{data["cpu"]}|{data["mem"]}|{data["time"]}|{data["gpu"]}'

        packet = PacketStruct.build(dict(
            command_protocol=CommandProtocol.OUT_SET_SMALL_WINDOW_DATA.value,
            length=None,
            data=data.encode('utf-8'),
        ))

        self._write_packet(packet)

    def set_buttons(self, buttons: Dict[int, Dict], *, update_only=False):
        zip_ready = self._prepare_zip(buttons)
        if not zip_ready:
            raise InvalidZipContent("Invalid bytes remained after mitigation; icons need regeneration")
        chunk_size = 1024

        data = b''
        # with open('bk/12345678-bug.zip', 'rb') as fp:
        with open(os.path.join('.build', 'build.zip'), 'rb') as fp:
            data += fp.read()

        file_size = len(data)

        command = CommandProtocol.OUT_PARTIALLY_UPDATE_BUTTONS if update_only else CommandProtocol.OUT_SET_BUTTONS
        chunk = data[:chunk_size - 8]
        packet = PacketStruct.build(dict(
            command_protocol=command.value,
            length=file_size,
            data=chunk.ljust(chunk_size - 8, b'\x00'),
        ))

        packets = [packet]

        for i in range(chunk_size - 8, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunk = chunk.ljust(chunk_size, b'\x00')
            packets.append(chunk)

        print('send_zip', file_size)
        self._write_packet(packets)

    def _parse_input(self, inp):
        try:
            parsed = IncomingStruct.parse(bytes(inp))
        except Exception as e:
            print('_parse_input', e)
            print(binascii.hexlify(bytes(inp)))
            return None

        data = parsed['data']
        if not data:
            return None

        command_protocol = parsed['command_protocol']
        if command_protocol == CommandProtocol.IN_DEVICE_INFO.value:
            print('_parse_input', data)
        elif command_protocol == CommandProtocol.IN_BUTTON.value:
            self._last_action_time = time.time()

            return ButtonAction(index=data['index'], pressed=data['pressed'], state=data['state'])

    def set_small_window_mode(self, mode):
        try:
            self._small_window_mode = SmallWindowMode(mode)
        except Exception:
            self._small_window_mode = SmallWindowMode.CLOCK

    def restore_small_window(self):
        self.set_small_window_data({
            'mode': self._small_window_mode,
        })

    def _prepare_zip(self, buttons: Dict) -> bool:
        manifest = {}

        shutil.rmtree('.build', ignore_errors=True)
        os.makedirs(os.path.join('.build', 'page', 'icons'), exist_ok=True)

        for button_index, button in buttons.items():
            button_index = int(button_index)
            row = button_index // self.BUTTON_COLS
            index = button_index % self.BUTTON_COLS

            button_data = {
                'State': 0,
                'ViewParam': [{}],
            }

            if button:
                if 'name' in button:
                    button_data['ViewParam'][0]['Text'] = button['name']

                if 'icon' in button:
                    # Copy icon
                    icon_name = button['icon']
                    icon_path = os.path.join('.cache', 'icons', '_generated', icon_name)
                    shutil.copyfile(icon_path, os.path.join('.build', 'page', 'icons', icon_name))

                    button_data['ViewParam'][0]['Icon'] = f'icons/{icon_name}'

            manifest[f'{index}_{row}'] = button_data

        page_path = os.path.join('.build', 'page')
        with open(os.path.join(page_path, 'manifest.json'), 'w') as fp:
            json.dump(manifest, fp, sort_keys=True, separators=(',', ':'), indent=2)

        # Chunks start with these bytes cause problems
        invalid_bytes = {b'\x00'[0], b'\x7c'[0]}
        padding_path = os.path.join(page_path, 'padding.bin')

        def _find_invalid(data: bytes):
            return [i for i in range(1016, len(data), 1024) if data[i:i + 1] and data[i] in invalid_bytes]

        try:
            # First attempt: build ZIP normally.
            compress_folder(page_path, '.build.zip', 1)

            with open('.build.zip', 'rb') as fp:
                zip_data = fp.read()

            file_size = len(zip_data)
            fixed_offsets = _find_invalid(zip_data)

            # If invalid bytes, try repeated padding rebuilds before byte patching.
            if fixed_offsets:
                for attempt in range(1, PADDING_ATTEMPTS + 1):
                    logger_fix.warning(
                        f'Invalid bytes detected at offsets {fixed_offsets} (size={file_size}); attempt {attempt}/{PADDING_ATTEMPTS} with padding {PADDING_SIZE} bytes'
                    )
                    with open(padding_path, 'wb') as fp:
                        fp.write(b'\x00' * PADDING_SIZE)

                    compress_folder(page_path, '.build.zip', 1)
                    with open('.build.zip', 'rb') as fp:
                        zip_data = fp.read()

                    file_size = len(zip_data)
                    fixed_offsets = _find_invalid(zip_data)

                    if not fixed_offsets:
                        logger_fix.info(f'Padding resolved invalid bytes on attempt {attempt}')
                        break

            if fixed_offsets:
                logger_fix.error(
                    f'Invalid bytes remain after {PADDING_ATTEMPTS} padding attempts at offsets {fixed_offsets} '
                    f'(size={file_size}); forcing regeneration'
                )
                return False
        finally:
            if os.path.exists(padding_path):
                try:
                    os.remove(padding_path)
                except OSError:
                    logger_fix.debug('Could not remove padding file (already removed?)')

        shutil.move('.build.zip', os.path.join('.build', 'build.zip'))
        return True
