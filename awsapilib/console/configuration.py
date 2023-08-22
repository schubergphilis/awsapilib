#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
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
Main code for configuration.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''20-06-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

METADATA_KEY: bytes = b'a\x03\x8fp4\x18\x97\x99:\xeb\xe7\x8b\x85\x97$4'

RESOLUTIONS = [(2560, 1080, 1055, 24),
               (2048, 864, 839, 30),
               (1920, 1080, 1040, 24),
               (1920, 810, 785, 30),
               (1680, 1050, 1025, 30),
               (1600, 1200, 1175, 30),
               (1600, 900, 875, 30),
               (1600, 676, 651, 30)]

VENDORS = [{'vendor': 'Nvidia', 'models': ['GeForce GT 1010',
                                           'GeForce GT 1030',
                                           'GeForce GTX 1050',
                                           'GeForce GTX 980',
                                           'GeForce GTX 970',
                                           'GeForce GTX 960 ',
                                           'GeForce GTX 780',
                                           'GeForce GTX 770',
                                           'GeForce GTX 760']},
           {'vendor': 'AMD', 'models': ['Radeon E9560',
                                        'Radeon E9390',
                                        'Radeon E9175']},
           {'vendor': 'Intel', 'models': ['UHD Graphics 770',
                                          'UHD Graphics 730',
                                          'UHD Graphics 710']},
           {'vendor': 'ASUS', 'models': ['GeForce RTX 3060 OC',
                                         'GeForce GT 4090',
                                         'GeForce GTX 4070']},
           {'vendor': 'Apple', 'models': ['Apple M1', 'Apple M2']},
           {'vendor': 'GIGABYTE', 'models': ['GeForce RTX 4090',
                                             'GeForce RTX 4080',
                                             'GeForce RTX 4070']},
           {'vendor': 'MSI', 'models': ['GeForce RTX 4090',
                                        'GeForce RTX 4080',
                                        'GeForce RTX 4070']}]
