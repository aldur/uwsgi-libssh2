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


REMOTE = "http://127.0.0.1:8080"


class TestUwsgiLibssh2(unittest.TestCase):
    server = None

    @classmethod
    def setUpClass(self):
        self.server = Thread(target=server_connect_and_wait, name="server")
        self.server.start()

    @classmethod
    def tearDownClass(self):
        EXIT_EVENT.set()
        # self.server.join()

    def test_sftp_transfer(self):
        resource = ("/foo", "tmp/foo.txt")

        request = requests.get(
            REMOTE + resource[0],
        )
        self.assertEqual(request.status_code, 200)
        self.assertEqual(request.headers['Content-Type'], "text/plain")
        with open(os.path.join(ROOT, resource[1]), "r") as f:
            self.assertEqual(request.text, f.read())

    def test_not_exists(self):
        resource = "/404"

        request = requests.get(
            REMOTE + resource,
        )
        self.assertEqual(request.status_code, 404)

    def test_big_image(self):
        resource = ("/img", "tmp/im_so_random.png")

        request = requests.get(
            REMOTE + resource[0],
        )
        self.assertEqual(request.status_code, 200)
        self.assertEqual(request.headers['Content-Type'], "image/png")
        self.assertEqual(
            int(request.headers['content-length']),
            int(os.path.getsize(os.path.join(ROOT, resource[1])))
        )

if __name__ == '__main__':
    unittest.main(warnings='ignore')
