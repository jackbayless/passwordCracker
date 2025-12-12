import hashlib



class PasswordCracker:
    def __init__(self):
        self.password = ""

    def detect_hash_type(self,hash):
        hash = hash.strip()
        length = len(hash)

        hex_chars = "0123456789abcdefABCDEF"

        if all(c in hex_chars for c in hash):
            if length == 32:
                return "md5"
            if length == 40:
                return "sha1"
            if length == 56:
                return "sha224"
            if length == 64:
                return "sha256"
            if length == 96:
                return "sha384"
            if length == 128:
                return "sha512"

        return None

    def detect_salted_hash(self, hash):
        if hash.startswith("$"):
            parts = hash.split("$")

            if parts[1] == "1":
                return ("md5-crypt", parts[2])  # salt
            if parts[1] == "5":
                return ("sha256-crypt", parts[2])
            if parts[1] == "6":
                return ("sha512-crypt", parts[2])
            if parts[1].startswith("2"):
                return ("bcrypt", parts[2][0:22])  # cost + salt
            if parts[1].startswith("argon2"):
                return ("argon2", "embedded")

        return None

    def crack_password(self, hash, filename):

        hash_funcs = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }

        hash_type = self.detect_hash_type(hash)

        if hash_type is None:
            print("Unsupported hash type, trying salted hash")
            hash_type = self.detect_salted_hash(hash)

        if hash_type is None:
            print("Unsupported hash type")
            return


        with open(filename, "r", errors="ignore") as file:
            for password in file:
                line = password.strip().encode("utf-8")
                line = hash_funcs[hash_type](line).hexdigest()

                if line == hash:
                    print(f"The password is: {password.strip()}")
                    print(f"Hash Type: {hash_type.strip()}")
                    return

            print("The password could not be found")



pass_filename = "passwords/rockyou_2025_00.txt"

password = "Wendy"

enc_password = password.encode("utf-8")
password_hash = hashlib.sha1(enc_password.strip()).hexdigest()

pc = PasswordCracker()
pc.crack_password(password_hash, pass_filename)

