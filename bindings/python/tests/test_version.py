import unittest

import libssig


class VersionTest(unittest.TestCase):
    def test_native_version(self):
        self.assertEqual(libssig.version(), (0, 1, 0))


if __name__ == "__main__":
    unittest.main()
