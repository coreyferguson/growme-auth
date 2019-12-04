
# SCIL Authentication

## Summary

Provides the authentication for all subdomains of scil.help.

## Deploy

Some of the instructions below will have `{parameter}` syntax below. Replace with these with relevant values.

### Once per stage

Some manual steps need to be performed once per stage.

Register an app with Google to obtain client id and secret using Step 1 in [this documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-social-idp.html#cognito-user-pools-social-idp-step-1).

Store those values in AWS Parameter Store

```bash
stage=dev ./node_modules/.bin/sls set-provider-secret \
  --client-id=clientIdValue \
  --secret=secretValue
```

### Ongoing

After once-per-storage instructions above and when re-deploying, simply:

```bash
stage={stage} npm run deploy
```
