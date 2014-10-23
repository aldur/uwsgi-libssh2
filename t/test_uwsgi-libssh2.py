#! /usr/bin/env python3
# coding = utf-8
# author = Adriano Di Luzio

# Simply launch me and I'll do the magic.
# I require paramiko and requests

import unittest
from ssh_server import server_connect_and_wait, ROOT, EXIT_EVENT
from threading import Thread
import requests
import os
import time


REMOTE = "http://127.0.0.1:8080"


class TestUwsgiLibssh2(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        server = Thread(target=server_connect_and_wait)
        server.start()

    @classmethod
    def tearDownClass(self):
        EXIT_EVENT.set()

    def _request_and_check_status_code(self, resource, status=200):
        request = requests.get(
            REMOTE + resource[0],
        )
        time.sleep(.1)
        self.assertEqual(request.status_code, status)

        return request

    def test_sftp_transfer(self):
        resource = ("/foo", "tmp/foo.txt")

        request = self._request_and_check_status_code(resource)
        self.assertEqual(request.headers['Content-Type'], "text/plain")
        with open(os.path.join(ROOT, resource[1]), "r") as f:
            self.assertEqual(request.text, f.read())

    def test_url_without_password(self):
        resource = ("/footris", "tmp/footris.txt")
        self._request_and_check_status_code(resource)

    def test_url_without_user_and_password(self):
        resource = ("/foobis", "tmp/foobis.txt")
        self._request_and_check_status_code(resource)

    def test_not_exists(self):
        resource = ("/404", None)
        self._request_and_check_status_code(resource, 404)

    def test_big_image(self):
        resource = ("/img", "tmp/im_so_random.png")

        request = self._request_and_check_status_code(resource)
        self.assertEqual(request.headers['Content-Type'], "image/png")
        self.assertEqual(
            int(request.headers['content-length']),
            int(os.path.getsize(os.path.join(ROOT, resource[1])))
        )

    def test_mountpoints(self):
        resources = [
            ("/foo/bar.txt", "mnt/foo/bar.txt"),
            ("/bar/user.txt", "home/bar/user.txt"),
        ]

        for resource in resources:
            request = self._request_and_check_status_code(resource)
            self.assertEqual(
                int(request.headers['content-length']),
                int(os.path.getsize(os.path.join(ROOT, resource[1])))
            )


if __name__ == '__main__':
    unittest.main(warnings='ignore', verbosity=2)
