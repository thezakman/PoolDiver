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

```bash
git clone https://github.com/TheZakMan/PoolDiver
cd PoolDiver
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
# Fetch credentials only
./PoolDiver.py -r us-east-1 -id us-east-1:00000000-0000-0000-0000-000000000000

# Fetch credentials and probe AWS service permissions
./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t

# Probe a specific subset of services
./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t -s s3,ec2,lambda
```

### Options

| Flag | Description |
|------|-------------|
| `-r`, `--region` | AWS region (required) |
| `-id`, `--identity` | Cognito Identity Pool ID (required) |
| `-t`, `--test` | Run AWS service permission tests |
| `-s`, `--services` | Comma-separated services to test (default: all) |
| `--no-enumerate` | Skip running `enumerate-iam` |
| `--enumerate-path` | Path to the `enumerate-iam` directory |
| `--output` | Custom output directory for results |
| `-v`, `--verbose` | Enable verbose logging |
| `--version` | Show version |

### enumerate-iam integration

PoolDiver looks for `enumerate-iam` via the `--enumerate-path` flag or the
`POOLDIVER_ENUMERATE_IAM` environment variable:

```bash
export POOLDIVER_ENUMERATE_IAM=~/Toolz/enumerate-iam
./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t
```

## Output

Everything is written under the working directory:

- `credentials/` — extracted credentials (JSON, one file per identity)
- `pool_diver_results/` — scan results (JSON), summary reports (TXT) and
  `enumerate-iam` output
- `pooldiver_output.log` — session audit log

These directories contain **sensitive data** and are git-ignored by default.

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
