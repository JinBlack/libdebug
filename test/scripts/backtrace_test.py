#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import unittest

from libdebug import debugger


class BacktraceTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/backtrace_test")

    def test_backtrace(self):
        d = self.d

        d.run()

        bp0 = d.breakpoint("main+8")
        bp1 = d.breakpoint("function1+8")
        bp2 = d.breakpoint("function2+8")
        bp3 = d.breakpoint("function3+8")
        bp4 = d.breakpoint("function4+8")
        bp5 = d.breakpoint("function5+8")
        bp6 = d.breakpoint("function6+8")

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp0.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:1], ["main+8"])

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp1.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+8", "main+22"])

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp2.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+8", "function1+18", "main+22"])

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp3.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+8", "function2+28", "function1+18", "main+22"]
        )

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp4.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+8", "function3+28", "function2+28", "function1+18", "main+22"],
        )

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp5.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:6],
            [
                "function5+8",
                "function4+28",
                "function3+28",
                "function2+28",
                "function1+18",
                "main+22",
            ],
        )

        d.cont()
        d.wait()

        self.assertTrue(d.rip == bp6.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:7],
            [
                "function6+8",
                "function5+28",
                "function4+28",
                "function3+28",
                "function2+28",
                "function1+18",
                "main+22",
            ],
        )

        d.kill()


if __name__ == "__main__":
    unittest.main()
