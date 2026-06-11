# PoolDiver 🤿

> *How deep can I go?*

**PoolDiver** extracts unauthenticated AWS credentials from a misconfigured
[Amazon Cognito Identity Pool](https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html)
and probes the AWS permissions those credentials grant — across S3, EC2,
Lambda, DynamoDB, IAM, SSM, Secrets Manager, SQS, SNS and RDS — in parallel,
with a live status bar. It can optionally chain into
[`enumerate-iam`](https://github.com/andresriancho/enumerate-iam) for deeper
enumeration.

> ⚠️ **Authorized use only.** Run PoolDiver exclusively against accounts you
> own or have written permission to assess (pentest engagement, bug bounty
> scope, or CTF).

---

## Install

Requires Python 3.9+.

**Globally, with pip** (exposes the `pooldiver` command):

```bash
pip install git+https://github.com/TheZakMan/PoolDiver
# or, from a local checkout:
git clone https://github.com/TheZakMan/PoolDiver && cd PoolDiver
pip install .          # add -e for an editable/dev install
```

**Or run straight from a checkout**, without installing:

```bash
git clone https://github.com/TheZakMan/PoolDiver && cd PoolDiver
pip install boto3 rich
python -m pooldiver --help
```

> The original single-file version is kept under [`legacy/`](legacy/) for reference.

## Usage

After a pip install, use the `pooldiver` command (equivalently
`python -m pooldiver` from a checkout):

```bash
# Fetch credentials only
pooldiver -r us-east-1 -id us-east-1:00000000-0000-0000-0000-000000000000

# Fetch credentials and probe AWS service permissions
pooldiver -r us-east-1 -id us-east-1:0000...0000 -t

# Probe a specific subset of services
pooldiver -r us-east-1 -id us-east-1:0000...0000 -t -s s3,ec2,lambda

# Enumerate S3 Amplify prefixes on a known bucket (when list_buckets is denied)
pooldiver -r us-east-1 -id us-east-1:0000...0000 -t -b my-amplify-bucket
```

### S3 enumeration for Cognito/Amplify

For Cognito-backed apps, `s3:ListAllMyBuckets` (`list_buckets`) is almost always
denied — access is scoped to per-prefix paths. PoolDiver therefore also lists the
standard Amplify prefixes on each target bucket:

- `public/`
- `protected/<identity-id>/`
- `private/<identity-id>/`

Pass the bucket name(s) with `--bucket` (find it in the app's `aws-exports.js`
/ `amplifyconfiguration.json`). The identity id is substituted automatically.

### Options

| Flag | Description |
|------|-------------|
| `-r`, `--region` | AWS region (required) |
| `-id`, `--identity` | Cognito Identity Pool ID (required) |
| `-t`, `--test` | Run AWS service permission tests |
| `-s`, `--services` | Comma-separated services to test (default: all) |
| `-b`, `--bucket` | S3 bucket(s) to enumerate for Amplify prefixes |
| `--no-enumerate` | Skip running `enumerate-iam` |
| `--enumerate-path` | Path to the `enumerate-iam` directory |
| `--output` | Custom output directory for results |
| `-w`, `--workers` | Max parallel workers for probing (default: 5) |
| `-v`, `--verbose` | Enable verbose logging |
| `--version` | Show version |

### enumerate-iam integration

PoolDiver **bundles** [`enumerate-iam`](https://github.com/andresriancho/enumerate-iam)
(under [`pooldiver/_vendor/`](pooldiver/_vendor/)), so it works out of the box —
no separate install needed. PoolDiver runs it as a separate subprocess.

To use a different copy, override the location (this takes precedence over the
bundled one):

```bash
export POOLDIVER_ENUMERATE_IAM=~/path/to/enumerate-iam   # or use --enumerate-path
pooldiver -r us-east-1 -id us-east-1:0000...0000 -t
```

Resolution order: `--enumerate-path` → `POOLDIVER_ENUMERATE_IAM` → bundled copy
→ common locations (`~/Toolz/enumerate-iam`, `~/tools/enumerate-iam`, …).

> The bundled `enumerate-iam` is **GPLv3** (its license is preserved in
> `pooldiver/_vendor/enumerate-iam/LICENSE`); PoolDiver itself is Apache 2.0.
> See [`pooldiver/_vendor/README.md`](pooldiver/_vendor/README.md).

## Output

All generated artifacts are written under a single `output/` directory in the
working directory:

- `output/credentials/` — extracted credentials (JSON, one file per identity)
- `output/results/` — scan results (JSON), summary reports (TXT) and
  `enumerate-iam` output
- `output/pooldiver_output.log` — session audit log

`output/` contains **sensitive data** and is git-ignored by default.
Use `--output <dir>` to redirect scan results elsewhere.

## Manual equivalent

PoolDiver automates what you can otherwise do by hand:

```bash
aws cognito-identity get-id \
  --identity-pool-id <IdentityPoolId> --region <Region>

aws cognito-identity get-credentials-for-identity \
  --identity-id <IdentityId> --region <Region>
```

## License

See [LICENSE](LICENSE).

---

Made by [@TheZakMan](https://github.com/TheZakMan)
