import json
from certmanager import FileSystemChallengeStore, FilesystemKeyStore, CertAuthority,Acme

key_store = FilesystemKeyStore("data")
challenge_store = FileSystemChallengeStore("./acme-challenges")  # this should be where your web server hosts the .well-known/acme-challenges.

certAuthority = CertAuthority(challenge_store, key_store,acme_url=Acme.URL_STAGING)
certAuthority.setup()

(response,_) = certAuthority.obtainCert("example.com")

json.dumps(response.__json__(),indent=2)