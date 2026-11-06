# Confidential Windows build broker

A generic manual-only GitHub Actions workflow for Windows projects supplied as secret inputs. This repository contains no application source or plaintext binaries.

- Standard public Windows runner; no larger runners, Actions cache, artifacts, subscriptions or RDP.
- ZIP input arrives through bounded INPUT_0 ... INPUT_9 repository secrets, authenticated by INPUT_SHA256.
- The input contains ci/cloud-plan.json describing its build/test commands.
- Private subprocess output stays in encrypted diagnostics, not public job logs.
- Final binaries and diagnostics are wrapped in AES-256-GCM using a key provided through OUTPUT_KEY. Only ciphertext is uploaded as a release asset.
- The workflow is manual-only and checkout credentials are not persisted. The ephemeral repository token publishes only the encrypted output.

Do not supply untrusted build input. An authorized build executes its code on the disposable hosted runner. Encryption protects output confidentiality; it does not establish correctness. Verify the enclosed test evidence after decryption.
