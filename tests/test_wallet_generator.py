import unittest
import subprocess
import json

class WalletGeneratorTest(unittest.TestCase):
    def test_wallet_output(self):
        result = subprocess.run(["python", "wallet_generator.py"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

        output = json.loads(result.stdout)
        self.assertIn("bitcoin", output)
        self.assertIn("ethereum", output)
        self.assertIn("solana", output)
        self.assertIn("secret_key_hex", output)

if __name__ == "__main__":
    unittest.main()
