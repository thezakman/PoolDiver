"""Real boto3 integration test for the S3 Amplify enumeration, via moto."""

import os
import boto3
import pytest
from moto import mock_aws

from pooldiver.logger import Log
from pooldiver.tester import ServiceTester

IDENTITY = "us-east-1:11111111-2222-3333-4444-555555555555"
OTHER = "us-east-1:99999999-8888-7777-6666-000000000000"
BUCKET = "myapp-userfiles-mobilehub-123456"


@pytest.fixture(autouse=True)
def _aws_creds():
    os.environ.update(
        AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
        AWS_SESSION_TOKEN="testing", AWS_DEFAULT_REGION="us-east-1",
    )


def _tester(tmp_path, **kw):
    log = Log(tmp_path / "t.log")
    session = boto3.Session(region_name="us-east-1")
    return ServiceTester(session, log, identity_id=IDENTITY, **kw)


@mock_aws
def test_enumerates_public_and_protected_prefixes(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    s3.put_object(Bucket=BUCKET, Key="public/logo.png", Body=b"img")
    s3.put_object(Bucket=BUCKET, Key="public/config.json", Body=b"{}")
    s3.put_object(Bucket=BUCKET, Key=f"protected/{IDENTITY}/note.txt", Body=b"mine")
    s3.put_object(Bucket=BUCKET, Key=f"protected/{OTHER}/leak.txt", Body=b"theirs")
    s3.put_object(Bucket=BUCKET, Key=f"private/{IDENTITY}/secret.txt", Body=b"priv")

    res = _tester(tmp_path, s3_buckets=[BUCKET])._s3()
    rp = res["readable_prefixes"][BUCKET]

    # public/ found with its two objects
    assert "public/" in rp and rp["public/"]["key_count"] == 2
    assert "public/logo.png" in rp["public/"]["sample"]
    # listing protected/ exposes BOTH identities' files (the juicy finding)
    assert rp["protected/"]["key_count"] == 2
    # identity-scoped prefix resolves to our own id
    assert f"protected/{IDENTITY}/" in rp
    assert rp[f"protected/{IDENTITY}/"]["key_count"] == 1
    # GetObject (HeadObject) confirmed on a real key (the first one listed)
    ro = rp["public/"]["readable_object"]
    assert "error" not in ro and ro["size"] > 0


@mock_aws
def test_write_test_puts_and_cleans_up(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)

    res = _tester(tmp_path, s3_buckets=[BUCKET], s3_write=True)._s3()
    wp = res["writable_prefixes"][BUCKET]

    assert wp["public/"]["wrote"] is True
    assert wp["public/"]["cleaned_up"] is True
    # the throwaway object was actually deleted
    listing = s3.list_objects_v2(Bucket=BUCKET, Prefix="public/")
    assert listing.get("KeyCount", 0) == 0


@mock_aws
def test_summary_reports_readable_and_writable(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    s3.put_object(Bucket=BUCKET, Key="public/a.txt", Body=b"a")

    t = _tester(tmp_path, s3_buckets=[BUCKET], s3_write=True)
    res = t._s3()
    summary = t._summarize("s3", res)
    assert "readable prefix" in summary
    assert "GET ok" in summary
    assert "WRITABLE" in summary


def test_candidate_buckets_from_mobilehub_role():
    from pooldiver.core import PoolDiver
    arn = ("arn:aws:sts::574177866690:assumed-role/"
           "personalhealth_unauth_MOBILEHUB_727385483/CognitoIdentityCredentials")
    assert PoolDiver._candidate_buckets(arn) == [
        "personalhealth-userfiles-mobilehub-727385483",
        "personalhealth-deployments-mobilehub-727385483",
        "personalhealth-hosting-mobilehub-727385483",
    ]
    assert PoolDiver._candidate_buckets(None) == []
    assert PoolDiver._candidate_buckets("arn:aws:iam::1:user/bob") == []


@mock_aws
def test_s3_list_paginates_all_objects(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    for i in range(60):                       # > S3_SAMPLE (25)
        s3.put_object(Bucket=BUCKET, Key=f"public/file{i:03d}.txt", Body=b"x")

    # default: sample only (capped at S3_SAMPLE)
    sampled = _tester(tmp_path, s3_buckets=[BUCKET])._s3()
    assert sampled["readable_prefixes"][BUCKET]["public/"]["key_count"] == 25

    # --s3-list: full pagination returns everything, with the full key list
    full = _tester(tmp_path, s3_buckets=[BUCKET], s3_list=True)._s3()
    pub = full["readable_prefixes"][BUCKET]["public/"]
    assert pub["key_count"] == 60
    assert len(pub["keys"]) == 60


class _DenyListBuckets:
    """Wrap an s3 client so list_buckets is denied (as it is for Cognito)."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def list_buckets(self, *a, **k):
        from botocore.exceptions import ClientError
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListBuckets")


class _DenySession:
    def __init__(self, inner):
        self._inner = inner

    def client(self, name, *a, **k):
        c = self._inner.client(name, *a, **k)
        return _DenyListBuckets(c) if name == "s3" else c


@mock_aws
def test_discovers_real_bucket_from_config_object(tmp_path):
    """A readable deployments bucket whose manifest names the real userfiles
    bucket should get that bucket discovered and probed automatically."""
    s3 = boto3.client("s3", region_name="us-east-1")
    deployments = "guessed-deployments-mobilehub-1"
    real_userfiles = "realapp-userfiles-mobilehub-999000111"
    s3.create_bucket(Bucket=deployments)
    s3.create_bucket(Bucket=real_userfiles)
    s3.put_object(
        Bucket=deployments, Key="mobile-hub-project.yml",
        Body=b"attributes:\n  user-files-bucket-name: realapp-userfiles-mobilehub-999000111\n",
    )
    s3.put_object(Bucket=real_userfiles, Key="public/loot.txt", Body=b"secret")

    # list_buckets denied; we only know the deployments bucket. The userfiles
    # one must be discovered from the manifest and probed.
    log = Log(tmp_path / "t.log")
    session = _DenySession(boto3.Session(region_name="us-east-1"))
    tester = ServiceTester(session, log, identity_id=IDENTITY,
                           s3_buckets=[deployments])
    res = tester._s3()

    assert real_userfiles in res.get("discovered_buckets", [])
    assert real_userfiles in res["readable_prefixes"]
    assert res["readable_prefixes"][real_userfiles]["public/"]["key_count"] == 1
