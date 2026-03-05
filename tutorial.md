# Tutorial: Nova App Template (Platform Deploy Only)

This tutorial only covers deploying through the Nova platform.

## 1. Prerequisites

- Nova portal account
- A reachable Git repository URL for this app
- (Optional) Foundry, if you also deploy the sample business contract

## 2. Create App (Portal)

1. Open Nova portal -> **Apps** -> **Create App**.
2. Fill:
   - `name`
   - `repo_url`
   - optional `description`, `metadata_uri`, `app_contract_addr`
3. Configure advanced options in the form (app listening port, KMS/App Wallet/S3/Helios toggles, chain list).
4. Submit and keep the returned app `sqid`.

Implementation notes:
- The portal can parse `enclaver.yaml` from your repo to prefill app listening port.
- App settings are persisted in control-plane `advanced_json`.

## 3. Create Version (Build)

1. Open app detail -> **Versions** -> **+ New Version**.
2. Provide:
   - `git_ref` (branch/tag/commit)
   - `version` (semantic version, e.g. `1.0.0`)
3. Trigger build and wait for status `success`.

Implementation notes:
- Build input is `git_ref + version`; repository is already bound to the app.
- Control-plane generates app-hub `nova-build.yaml` and `enclaver.yaml` from app settings, then triggers workflow.

## 4. Deploy Version

1. Select a successful version and click **Deploy this version**.
2. Choose `region` and `tier` (`standard` or `performance`).
3. Submit deployment and monitor state in **Deployments**.

Implementation notes:
- Deploy request fields are `build_id`, `region`, optional `tier`, optional `app_contract_addr`.
- Current deploy modal does not expose environment-variable input fields.

## 5. Optional On-Chain Lifecycle

If your app workflow needs registry/on-chain records:
1. Create app on-chain (`create-onchain`).
2. Enroll build on-chain (`builds/{id}/enroll`).
3. Generate proof (`zkproof/generate`).
4. Register instance on-chain (`instance/register`).

## 6. Troubleshooting

- Build stuck or failed:
  - Check app-hub GitHub Actions run from the version panel.
- Deployment fails early:
  - Confirm selected build is `success` and has `image_uri`.
- KMS/App Wallet checks fail in app API:
  - Verify the app was created with matching advanced toggles in portal.

## 7. Learning Index

See [`README.md`](./README.md) section **Module Learning Map (Functionality + APIs + Implementation)** for endpoint-by-endpoint learning and reuse entry points.
