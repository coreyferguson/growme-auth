
const CognitoUserPoolIdpGoogle = require('../../../../build/impl/cognitoUserPoolIdpGoogle').CognitoUserPoolIdpGoogle;
const userPool = require('../../../support/stubs/aws-sdk/stubCognitoIdentityServiceProvider');
const userPoolFacade = require('../../../support/stubs/build/aws-facades/stubCognitoUserPoolFacade');
const ssm = require('../../../support/stubs/aws-sdk/stubSsm');
const { expect, sinon } = require('../../../support/TestUtilities');

describe('cognitoUserPoolIdpGoogle', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('isDone - true', async () => {
    const command = new CognitoUserPoolIdpGoogle({ userPool, userPoolFacade });
    const response = describeIdentityProviderResponse;
    sandbox.stub(userPool, 'describeIdentityProvider').returns({ promise: () => Promise.resolve(response) });
    await expect(command.isDone({ service: 'overattribution-auth', stage: 'test' })).to.eventually.be.true;
  });

  it('isDone - false', async() => {
    const command = new CognitoUserPoolIdpGoogle({ userPool, userPoolFacade });
    const response = describeIdentityProviderResponse;
    const error = new Error('no idp');
    error.code = 'ResourceNotFoundException';
    sandbox.stub(userPool, 'describeIdentityProvider').returns({ promise: () => Promise.reject(error) });
    await expect(command.isDone({ service: 'overattribution-auth', stage: 'test' })).to.eventually.be.false;
  });

  it('do - unknown error', async () => {
    const command = new CognitoUserPoolIdpGoogle({ userPool, userPoolFacade });
    sandbox.stub(userPool, 'createIdentityProvider').returns({ promise: () => Promise.reject(new Error('oops')) });
    sandbox.stub(command, 'getCredentials').returns({});
    await expect(command.do({ service: 'overattribution-auth', stage: 'test' })).to.be.rejectedWith('oops');
  });

  it('undo - unknown error', async () => {
    const command = new CognitoUserPoolIdpGoogle({ userPool, userPoolFacade });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns(Promise.resolve());
    sandbox.stub(userPool, 'deleteIdentityProvider').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.undo({ service: 'overattribution-auth', stage: 'test' })).to.be.rejectedWith('oops');
  });

  it('getCredentials - success', async () => {
    const command = new CognitoUserPoolIdpGoogle({ ssm });
    sandbox.stub(ssm, 'getParameters').returns({
      promise: () => Promise.resolve({
        "Parameters": [
          {
            "Name": "/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID",
            "Type": "SecureString",
            "Value": "1234",
            "Version": 1,
            "LastModifiedDate": "2019-08-31T18:09:46.492Z",
            "ARN": "arn:aws:ssm:us-west-2:123456789012:parameter/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID"
          },
          {
            "Name": "/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_SECRET",
            "Type": "SecureString",
            "Value": "4321",
            "Version": 1,
            "LastModifiedDate": "2019-08-31T18:09:47.159Z",
            "ARN": "arn:aws:ssm:us-west-2:123456789012:parameter/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_SECRET"
          }
        ],
        "InvalidParameters": []
      })
    });
    const credentials = await command.getCredentials('overattribution-auth', 'test');
    expect(credentials).to.deep.equal({
      COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID: '1234',
      COGNITO_USER_POOL_IDP_GOOGLE_SECRET: '4321'
    });
  });

  it('getCredentials - missing parameter', async () => {
    const command = new CognitoUserPoolIdpGoogle({ ssm });
    sandbox.stub(ssm, 'getParameters').returns({
      promise: () => Promise.resolve({
        "Parameters": [
          {
            "Name": "/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID",
            "Type": "SecureString",
            "Value": "1234",
            "Version": 1,
            "LastModifiedDate": "2019-08-31T18:09:46.492Z",
            "ARN": "arn:aws:ssm:us-west-2:123456789012:parameter/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID"
          }
        ],
        "InvalidParameters": [
          "/overattribution-auth/test/COGNITO_USER_POOL_IDP_GOOGLE_SECRET"
        ]
      })
    });
    await expect(command.getCredentials('overattribution-auth', 'test')).to.eventually.be.rejected;
  });

});

const describeIdentityProviderResponse = {
  "IdentityProvider": {
    "UserPoolId": "us-west-2_abCdEfG12",
    "ProviderName": "Google",
    "ProviderType": "Google",
    "ProviderDetails": {
      "attributes_url": "https://people.googleapis.com/v1/people/me?personFields=",
      "attributes_url_add_attributes": "true",
      "authorize_scopes": "profile email openid",
      "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
      "client_id": "123456789012-abcdef34ghijk5lmnop67q8rs9tuvwx0.apps.googleusercontent.com",
      "client_secret": "a_bcDE123FGhij_KlMnOPQRS",
      "oidc_issuer": "https://accounts.google.com",
      "token_request_method": "POST",
      "token_url": "https://www.googleapis.com/oauth2/v4/token"
    },
    "AttributeMapping": {
      "email": "email",
      "profile": "profile",
      "username": "sub"
    },
    "IdpIdentifiers": [],
    "LastModifiedDate": "2019-08-30T21:45:38.028Z",
    "CreationDate": "2019-08-30T21:44:50.934Z"
  }
};
