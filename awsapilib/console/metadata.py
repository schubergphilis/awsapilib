#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: metadata.py
#
# Copyright 2023 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for metadata.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import base64
import json
import struct
import time
from dataclasses import dataclass
from random import randint, choice
from typing import List, Tuple, Union, Optional

import binascii
import math
from fake_useragent import UserAgent

from .configuration import METADATA_KEY, VENDORS, RESOLUTIONS
from .consoleexceptions import (XXTEAException,
                                InvalidMetadata,
                                InvalidDecryption,
                                EncryptionFailure,
                                DecryptionFailure)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''20-06-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class XXTEA:
    """XXTEA encryption class.

    Note:
        Info can be found at: https://en.wikipedia.org/wiki/XXTEA?useskin=vector
        Initial python implementation can be found at: from https://github.com/andersekbom/prycut
    """

    def __init__(self, key: Union[str, bytes]) -> None:
        """Initializes with the given key.

        Note:
            The key must be 128-bit (16 characters) in length.
        """
        key = key.encode() if isinstance(key, str) else key
        if len(key) != 16:
            raise XXTEAException('Invalid key')
        self.key = struct.unpack('IIII', key)
        assert len(self.key) == 4

    @staticmethod
    def _xxtea(v: List, n: int, k: Union[List, Tuple]) -> int:
        assert isinstance(v, list)
        assert isinstance(n, int)
        assert isinstance(k, (list, tuple))

        def mx():
            return ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum_ ^ y) + (
                k[(p & 3) ^ e] ^ z)

        def u32(x):
            return x % 2 ** 32

        y = v[0]
        sum_ = 0
        delta = 2654435769
        if n > 1:  # Encoding
            z = v[n - 1]
            q = math.floor(6 + (52 / n // 1))
            while q > 0:
                q -= 1
                sum_ = u32(sum_ + delta)
                e = u32(sum_ >> 2) & 3
                p = 0
                while p < n - 1:
                    y = v[p + 1]
                    z = v[p] = u32(v[p] + mx())
                    p += 1
                y = v[0]
                z = v[n - 1] = u32(v[n - 1] + mx())
            return 0

        if n < -1:  # Decoding
            n = -n
            q = math.floor(6 + (52 / n // 1))
            sum_ = u32(q * delta)
            while sum_ != 0:
                e = u32(sum_ >> 2) & 3
                p = n - 1
                while p > 0:
                    z = v[p - 1]
                    y = v[p] = u32(v[p] - mx())
                    p -= 1
                z = v[n - 1]
                y = v[0] = u32(v[0] - mx())
                sum_ = u32(sum_ - delta)
            return 0
        return 1

    @staticmethod
    def _bytes_to_longs(data: Union[str, bytes]) -> List[int]:
        data_bytes = data.encode() if isinstance(data, str) else data
        return [int.from_bytes(data_bytes[i:i + 4], 'little')
                for i in range(0, len(data_bytes), 4)]

    @staticmethod
    def _longs_to_bytes(data: List[int]) -> bytes:
        return b''.join([i.to_bytes(4, 'little') for i in data])

    @staticmethod
    def generate_hex_checksum(data: str) -> str:
        block_size = 8
        checksum = binascii.crc32(data.encode()) % 2 ** 32
        checksum = format(checksum, 'X')
        return checksum.zfill(block_size) if len(checksum) < block_size else checksum

    def _process(self, data: Union[str, bytes], mode: str = 'encrypt'):
        ldata = math.ceil(len(data) / 4)
        idata = self._bytes_to_longs(data)
        ldata = -ldata if mode == 'decrypt' else ldata
        if self._xxtea(idata, ldata, self.key) != 0:
            raise XXTEAException
        return self._longs_to_bytes(idata)

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """Encrypts and returns a block of data."""
        try:
            return self._process(data)
        except XXTEAException:
            raise EncryptionFailure from None

    def decrypt(self, data: Union[str, bytes]) -> bytes:
        """Decrypts and returns a block of data."""
        try:
            return self._process(data, mode='decrypt').rstrip(b'\0')
        except XXTEAException:
            raise DecryptionFailure from None


class Lsubid:
    """Models the lsubid creation for aws metadata."""

    def __init__(self, user_agent):
        self.user_agent = user_agent

    @staticmethod
    def _string_to_small_float(data: Union[str, int] = ''):
        """Converts a provided string to a very small float."""
        t = 402871197
        data = str(data)
        for character in data:
            t += ord(character)
            n = 0.02519603282416938 * t
            t = int(n) & 0xFFFFFFFF
            n -= t
            n *= t
            t = int(n) & 0xFFFFFFFF
            n -= t
            t += 4294967296 * n
        return 23283064365386964e-26 * (int(t) & 0xFFFFFFFF)

    def _get_seed_values(self, timestamp: int):
        """Initialises seed values of r, n, i and o.

        Calculate values based on the user agent set and the timestamp that it has run on, along with a hard coded div.

        returns:
            Calculated values of r, n, i and o

        """
        value = self._string_to_small_float(' ')
        r = n = i = value
        o = 1
        seed_table = ['<div id="a-popover-root" style="z-index:-1;position:absolute;"></div>',
                      self.user_agent,
                      timestamp]
        for entry in seed_table:
            for variable in (r, n, i):
                variable -= self._string_to_small_float(entry)
                if variable < 0:
                    variable += 1
        return r, n, i, o

    def _slice_from_seed_values(self, slice_size: int, timestamp: int):
        """Returns a size of provided slice_size from the calculated number."""
        r, n, i, o = self._get_seed_values(timestamp)
        e = 2091639 * r + 23283064365386964e-26 * o
        o = int(e // 1)
        i = e - o
        return str(int(4294967296 * i))[-slice_size:].zfill(slice_size)

    def new(self, timestamp: Optional[int] = None):
        """Generates a new lsubid.

        If a timestamp is not provided (used for testing) it will apply the current timestamp on the calculation.

        Returns:
            A string of the form of "X00-0000000-0000000-1234567891234"

        """
        timestamp = timestamp if timestamp else int(time.time() * 1000)
        first_part = self._slice_from_seed_values(2, timestamp)
        second_part = self._slice_from_seed_values(7, timestamp)
        third_part = self._slice_from_seed_values(7, timestamp)
        return f'X{first_part}-{second_part}-{third_part}:{timestamp}'


@dataclass
class Resolution:
    """Models a screen resolution and the required representation for metadata1."""
    width: int
    height: int
    other: int
    rate: int = 30

    def __str__(self):
        return f'{self.width}-{self.height}-{self.other}-{self.rate}-*-*-*'

    @property
    def to_string(self):
        return str(self)


class MetadataManager:
    """Creates random valid metadata."""

    resolutions = [Resolution(*data) for data in RESOLUTIONS]

    def __init__(self, user_agent=None):
        self.xxtea = XXTEA(METADATA_KEY)
        self.user_agent = user_agent if user_agent else UserAgent().random
        self._lsubid = Lsubid(self.user_agent)
        self._resolution = None
        vendor = choice(VENDORS)
        self._vendor = vendor.get('vendor')
        self._vendor_model = choice(vendor.get('models'))
        self._metadata_valid_prefix = 'ECdITeCs:'
        self._referer = 'https://console.aws.amazon.com/'

    @property
    def resolution(self):
        """The random chosen resolution."""
        if self._resolution is None:
            self._resolution = choice(self.resolutions)
        return self._resolution

    @property
    def metadata_version(self):
        """Metadata version."""
        return '4.0.0'

    @property
    def screen_info(self):
        """The required string representation of the random resolution."""
        return self.resolution.to_string

    @property
    def plugins(self):
        """Reported plugins."""
        return 'PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge PDF Viewer WebKit built-in PDF'

    def _generate_metadata(self, redirect_url):
        """Generates random valid metadata using the provided redirect_url.

        redirect_url: The url with a valid redirect for authentication.

        Returns:
            A json string of the generated metadata.

        """
        start = lambda: int(time.time() * 1000)  # noqa
        end_short = lambda: int(time.time() * 1000) + randint(0, 100)  # noqa
        end_long = lambda: int(time.time() * 1000) + randint(400000, 600000)  # noqa
        key_presses = randint(0, 10)
        mouse_cycles = randint(3, 12)
        data = {'userAgent': self.user_agent,
                'version': self.metadata_version,
                'location': redirect_url,
                'lsUbid': self._lsubid.new(),
                'plugins': f'{self.plugins} ||{self.screen_info}',
                'dupedPlugins': f'{self.plugins} ||{self.screen_info}',
                'referrer': self._referer,
                'screenInfo': self.screen_info,
                'start': start(),
                'end': end_long(),
                'timeZone': randint(-12, 14),
                'dnt': 1,
                'errors': [],
                'flashVersion': None,
                'form': {},
                'history': {'length': 0},
                'auth': {'form': {'method': 'get'}},
                'interaction': {'clicks': randint(0, 10),
                                'copies': 0,
                                'cuts': 0,
                                'keyCycles': [randint(0, 20000) for _ in range(key_presses)],
                                'keyPressTimeIntervals': [randint(0, 30000) for _ in range(key_presses)],
                                'keyPresses': key_presses,
                                'mouseClickPositions': [f'{randint(0, self.resolution.width)},'
                                                        f'{randint(0, self.resolution.height)}'
                                                        for _ in range(mouse_cycles)],
                                'mouseCycles': [randint(50, 120) for _ in range(mouse_cycles)],
                                'pastes': randint(0, 10),
                                'touchCycles': [],
                                'touches': 0},
                'automation': {'phantom': {'properties': {'window': []}},
                               'wd': {'properties': {'document': [],
                                                     'navigator': [],
                                                     'window': []}}},
                'canvas': {'emailHash': None,
                           'hash': 0,
                           'histogramBins': []},
                'capabilities': {'css': {'WebkitTextStroke': 1,
                                         'borderImage': 1,
                                         'borderRadius': 1,
                                         'boxShadow': 1,
                                         'opacity': 1,
                                         'textShadow': 1,
                                         'transform': 1,
                                         'transition': 1},
                                 'elapsed': 0,
                                 'js': {'audio': True,
                                        'geolocation': True,
                                        'localStorage': 'supported',
                                        'touch': True,
                                        'video': True,
                                        'webWorker': True}},
                'gpu': {'extensions': ['ANGLE_instanced_arrays',
                                       'EXT_blend_minmax',
                                       'EXT_color_buffer_half_float',
                                       'EXT_float_blend',
                                       'EXT_frag_depth',
                                       'EXT_shader_texture_lod',
                                       'EXT_sRGB',
                                       'EXT_texture_compression_rgtc',
                                       'EXT_texture_filter_anisotropic',
                                       'OES_element_index_uint',
                                       'OES_fbo_render_mipmap',
                                       'OES_standard_derivatives',
                                       'OES_texture_float',
                                       'OES_texture_float_linear',
                                       'OES_texture_half_float',
                                       'OES_texture_half_float_linear',
                                       'OES_vertex_array_object',
                                       'WEBGL_color_buffer_float',
                                       'WEBGL_compressed_texture_s3tc',
                                       'WEBGL_compressed_texture_s3tc_srgb',
                                       'WEBGL_debug_renderer_info',
                                       'WEBGL_debug_shaders',
                                       'WEBGL_depth_texture',
                                       'WEBGL_draw_buffers',
                                       'WEBGL_lose_context',
                                       'WEBGL_provoking_vertex'],
                        'model': self._vendor_model,
                        'vendor': self._vendor},
                'math': {'cos': '-0.5753861119575491',
                         'sin': '0.8178819121159085',
                         'tan': '-1.4214488238747243'},
                'metrics': {'auto': randint(0, 10),
                            'batt': randint(0, 10),
                            'browser': randint(0, 9999),
                            'canvas': randint(0, 10),
                            'capabilities': randint(0, 10),
                            'captchainput': randint(0, 10),
                            'dnt': randint(0, 10),
                            'el': randint(0, 10),
                            'fp2': randint(10000, 555555),
                            'gpu': randint(0, 10),
                            'h': randint(0, 10),
                            'input': randint(0, 10),
                            'lsubid': randint(0, 9999),
                            'math': randint(0, 10),
                            'perf': randint(0, 10),
                            'pow': randint(0, 10),
                            'script': randint(0, 10),
                            'tts': randint(0, 10),
                            'tz': randint(0, 9999)},
                'performance': {'timing': {'connectEnd': end_short(),
                                           'connectStart': start(),
                                           'domComplete': start(),
                                           'domContentLoadedEventEnd': end_short(),
                                           'domContentLoadedEventStart': start(),
                                           'domInteractive': start(),
                                           'domLoading': start(),
                                           'domainLookupEnd': end_short(),
                                           'domainLookupStart': start(),
                                           'fetchStart': start(),
                                           'loadEventEnd': end_short(),
                                           'loadEventStart': start(),
                                           'navigationStart': start(),
                                           'redirectEnd': 0,
                                           'redirectStart': 0,
                                           'requestStart': start(),
                                           'responseEnd': end_short(),
                                           'responseStart': start(),
                                           'secureConnectionStart': start(),
                                           'unloadEventEnd': 0,
                                           'unloadEventStart': 0}},
                'scripts': {'dynamicUrlCount': 0,
                            'dynamicUrls': [],
                            'inlineHashes': [],
                            'inlineHashesCount': 0},
                'token': {'isCompatible': True, 'pageHasCaptcha': 0},
                'webDriver': False}
        return json.dumps(data)

    def get_random_metadata(self, redirect_url):
        """Generates metadata.

        Returns:
            The random metadata in the expected encrypted form.

        """
        return self._encrypt_metadata(self._generate_metadata(redirect_url))

    def _encrypt_metadata(self, metadata: str) -> str:
        """Encrypts metadata to be used to log in to Amazon

        Returns:
            The encrypted metadata.

        """
        checksum = XXTEA.generate_hex_checksum(metadata)
        encrypted = self.xxtea.encrypt(f"{checksum}#{metadata}")
        return f'{self._metadata_valid_prefix}:{base64.b64encode(encrypted).decode("utf-8")}'

    def decrypt_metadata(self, metadata: str) -> str:
        """Decrypts metadata.

        Returns:
            The decrypted metadata.

        Raises:
            InvalidMetadata: If the metadata does not start with the expected suffix
            InvalidDecryption: If the decryption checksum does not match the one in the payload.

        """
        if not metadata.startswith(self._metadata_valid_prefix):
            raise InvalidMetadata(f'Invalid encrypted metadata, payload should start with '
                                  f'"{self._metadata_valid_prefix}"')
        encrypted = base64.b64decode(metadata[9:].encode('utf-8'))
        payload = self.xxtea.decrypt(encrypted).decode('utf-8')
        checksum, metadata = payload.split('#', 1)
        if XXTEA.generate_hex_checksum(metadata) != checksum:
            raise InvalidDecryption('Calculated checksum and provided checksum do not match.')
        return metadata
