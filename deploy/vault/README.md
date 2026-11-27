# Time testnet password vault

The wallet at `https://wallet.testnet.thetimenetwork.org` opens `https://vault.testnet.thetimenetwork.org` for enrollment and individual unlocks. Publish both sites from the same release. The vault stores encrypted account records in the user's browser. Its server only supplies static application files.

## Local preview

Run `node web-v4/wallet/tests/preview-server.mjs --port 8780` from the repository root. Visit `http://localhost:8780/__protect?on=1` to enable protected signup on the mock chain, then open `http://localhost:8780/`. The vault runs at `http://localhost:8786/`. The preview exercises the interface and intentionally stops before chain registration. For a configured protected devnet, the gateway also starts the local vault when it binds the wallet at port 8780. Preserve the same browser profile and hostname across visits.

## Testnet deployment

Build into a fresh directory.

```sh
node deploy/vault/build.mjs vault-release
```

The build writes `assets/` and `testnet-stack.json`. The template creates a read-only CloudFront distribution, a private S3 bucket for application code, and the records for the vault hostname. CloudFront authenticates its HTTPS origin reads. Install it in the account that owns the public Route 53 zone, using an issued ACM certificate in us-east-1 covering the hostname. Set `TIME_VAULT_CERTIFICATE` and `TIME_VAULT_ZONE` to those identifiers.

```sh
aws cloudformation deploy --stack-name time-testnet-vault --template-file vault-release/testnet-stack.json --parameter-overrides CertificateArn="$TIME_VAULT_CERTIFICATE" HostedZoneId="$TIME_VAULT_ZONE"
bucket=$(aws cloudformation describe-stacks --stack-name time-testnet-vault --query 'Stacks[0].Outputs[?OutputKey==`AssetBucket`].OutputValue | [0]' --output text)
aws s3 cp vault-release/assets "s3://$bucket/" --recursive --exclude '*' --include '*.js' --include '*.mjs' --content-type 'text/javascript; charset=utf-8' --cache-control no-store
aws s3 cp vault-release/assets/manager.css "s3://$bucket/manager.css" --content-type 'text/css; charset=utf-8' --cache-control no-store
aws s3 cp vault-release/assets/index.html "s3://$bucket/index.html" --content-type 'text/html; charset=utf-8' --cache-control no-store
```

Upload the HTML last. Open the vault over HTTPS and complete enrollment and a payment unlock on a PRF-capable device before enabling the wallet release. Device prompts and passkey synchronization vary by platform. The offline recovery words are the independent way back after device or browser storage loss.
