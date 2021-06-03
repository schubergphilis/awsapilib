#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: console.py
#
# Copyright 2021 Costas Tyfoxylos
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
Main code for console.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''30-06-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''console'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

from requests import Session
from bs4 import BeautifulSoup as Bfs
import urllib

session=Session()

email = 'ROOT_EMAIL_HERE'

url='https://console.aws.amazon.com/console/home?hashArgs=%23a'
params = {'action': 'resolveAccountType',
		  'email':  email}

response = session.get(url, params=params)

soup = Bfs(response.text, features="html.parser")
csrf_token = soup.find('meta',{'name':'csrf_token'}).attrs.get('content')
session_id = soup.find('meta',{'name':'session_id'}).attrs.get('content')

signin_url = 'https://signin.aws.amazon.com/signin'
params.update({'csrf': csrf_token})
signin_response = session.post(signin_url, data=params)
captcha_url = signin_response.json().get('properties').get('CaptchaURL')

solver = Iterm()
captcha = solver.solve(captcha_url)

params.update({'captcha_guess': captcha,
               'captcha_token': signin_response.json().get('properties').get('CES'),
               'captchaObfuscationToken': signin_response.json().get('properties').get('captchaObfuscationToken')})

final_response = session.post(signin_url, data=params)

params = {'action': 'captcha',
		  'forgotpassword':  True,
          'csrf': session.cookies.get('aws-signin-csrf')}
response_reset_password = session.post(signin_url, data=params)
captcha_url = response_reset_password.json().get('properties').get('CaptchaURL')

captcha = solver.solve(captcha_url)
params = {'action': 'getResetPasswordToken',
		  'email':  email,
          'csrf': session.cookies.get('aws-signin-csrf')}
params.update({'captcha_guess': captcha,
               'captcha_token': response_reset_password.json().get('properties').get('CES'),
               'captchaObfuscationToken': response_reset_password.json().get('properties').get('captchaObfuscationToken')})
completed_response = session.post(signin_url, data=params)


# get the url from the email
reset_url = input('Reset URL: ')
parsed_url = urllib.parse.parse_qs(reset_url)
response = session.get(reset_url)
token = parsed_url.get('token').pop()
key = parsed_url.get('key').pop()
new_password = input('Password:')
params = {
		'action':          'resetPasswordSubmitForm',
		'confirmpassword': new_password,
		'key':             key,
		'newpassword':     new_password,
		'token':           token,
		'type':            'RootUser',
        'csrf': session.cookies.get('aws-signin-csrf', path='/resetpassword')
	}
reset_url = 'https://signin.aws.amazon.com/resetpassword'
reset_response = session.post(reset_url, data=params)
