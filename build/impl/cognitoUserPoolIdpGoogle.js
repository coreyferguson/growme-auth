
const AWS = require('aws-sdk');
const BuildCommand = require('../BuildCommand');
const userPoolFacade = require('../aws-facades/cognitoUserPoolFacade');

class CognitoUserPoolIdpGoogle extends BuildCommand {

  constructor(options) {
    super(options);
    options = options || {};
    this.userPool = options.userPool
      || new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18', region: 'us-west-2' });
    this.ssm = options.ssm || new AWS.SSM({ apiVersion: '2014-11-06', region: 'us-west-2' });
    this.userPoolFacade = options.userPoolFacade || userPoolFacade;
  }

  getName() {
    return 'cognitoUserPoolIdpGoogle';
  }

  async do(options) {
    options = options || {};
    const { service, stage } = options;
    const UserPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    const credentials = await this.getCredentials(service, stage);
    await this.userPool.createIdentityProvider({
      ProviderDetails: {
        attributes_url: 'https://people.googleapis.com/v1/people/me?personFields=',
        attributes_url_add_attributes: 'true',
        authorize_scopes: 'profile email openid',
        authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth',
        client_id: credentials.COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID,
        client_secret: credentials.COGNITO_USER_POOL_IDP_GOOGLE_SECRET,
        oidc_issuer: 'https://accounts.google.com',
        token_request_method: 'POST',
        token_url: 'https://www.googleapis.com/oauth2/v4/token'
      },
      ProviderName: 'Google',
      ProviderType: 'Google',
      UserPoolId,
      AttributeMapping: {
        email: 'email',
        profile: 'profile',
        username: 'sub'
      },
      IdpIdentifiers: []
    }).promise();
  }

  async undo(options) {
    options = options || {};
    const { service, stage } = options;
    const UserPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    await this.userPool.deleteIdentityProvider({
      ProviderName: 'Google',
      UserPoolId
    }).promise();
  }

  async isDone(options) {
    options = options || {};
    const { service, stage } = options;
    const UserPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    try {
      const response = await this.userPool.describeIdentityProvider({
        ProviderName: 'Google',
        UserPoolId
      }).promise();
      return !!response.IdentityProvider;
    } catch (error) {
      if (/ResourceNotFoundException/.test(error.code)) return false;
      else throw error;
    };
  }

  async getCredentials(service, stage) {
    const response = await this.ssm.getParameters({
      Names: [
        `/${service}/${stage}/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID`,
        `/${service}/${stage}/COGNITO_USER_POOL_IDP_GOOGLE_SECRET`
      ],
      WithDecryption: true
    }).promise();
    if (response.InvalidParameters && response.InvalidParameters.length > 0)
      throw new Error(`Missing required credentials: ${response.InvalidParameters}`);
    const credentials = response.Parameters
      .map(item => {
        item.Name = item.Name.replace(`/${service}/${stage}/`, '');
        return item;
      })
      .reduce((agg, item) => {
        agg[item.Name] = item.Value
        return agg;
      }, {});
    return credentials;
  }

}

module.exports = new CognitoUserPoolIdpGoogle();
module.exports.CognitoUserPoolIdpGoogle = CognitoUserPoolIdpGoogle;
