"""
 Copyright 2016, 2018 John J. Rofrano. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
# Test cases can be run with any of the following:
# coverage report -m --include=service.py
# nosetests -v --rednose --with-coverage --cover-package=service

import unittest
import json
from base64 import b64encode
import service

######################################################################
#  T E S T   C A S E S
######################################################################
class TestPetServer(unittest.TestCase):

    def setUp(self):
        service.app.debug = True
        self.app = service.app.test_client()
        service.API_USERNAME = "tester"
        service.API_PASSWORD = "s3cr3t"
        self.headers = {
            'Authorization': 'Basic %s' % \
            b64encode(b'{}:{}'.format(service.API_USERNAME, service.API_PASSWORD))
        }

    def login(self):
        resp = self.app.get('/login', headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.data) > 0)
        data = json.loads(resp.data)
        return data['token']

    def test_index(self):
        """ Test the home page which is not protected """
        resp = self.app.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('Example Flask JWT Demo' in resp.data)

    def test_not_authorized(self):
        """ Test call that is not autorized """
        resp = self.app.get('/hello')
        self.assertEqual(resp.status_code, 401)

    def test_say_hello(self):
        """ Test call with autorization """
        token = self.login()
        headers = {
            'Authorization': 'Bearer %s' % token
        }
        resp = self.app.get('/hello', headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.data) > 0)
        data = json.loads(resp.data)
        self.assertEqual(data['hello'], service.API_USERNAME)


######################################################################
#   M A I N
######################################################################
if __name__ == '__main__':
    unittest.main()
