
const BuildCommand = require('../BuildCommand');
const AWS = require('aws-sdk');
const userPoolFacade = require('../aws-facades/cognitoUserPoolFacade');

class CognitoIdentityPoolProvider extends BuildCommand {

  constructor(options) {
    super(options);
    options = options || {};
    this.identity = options.identity || new AWS.CognitoIdentity({ region: 'us-west-2', apiVersion: '2014-06-30' });
    this.userPoolFacade = options.userPoolFacade || userPoolFacade;
  }

  getName() {
    return 'cognitoIdentityPoolProvider';
  }

  async do(options) {
    options = options || {};
    const { config, service, stage } = options;
    const userPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    const clientId = await this.userPoolFacade.getClientId(service, stage, 'flash');
    const IdentityPoolId = await this.getIdentityPoolId(config.identityPoolName);
    const identityPool = await this.identity.describeIdentityPool({ IdentityPoolId }).promise();
    identityPool.CognitoIdentityProviders = identityPool.CognitoIdentityProviders || [];
    identityPool.CognitoIdentityProviders.push(this.newCognitoIdentityProvider(userPoolId, clientId));
    await this.identity.updateIdentityPool(identityPool).promise();
  }

  async undo(options) {
    options = options || {};
    const { config, service, stage } = options;
    const IdentityPoolId = await this.getIdentityPoolId(config.identityPoolName);
    const identityPool = await this.identity.describeIdentityPool({ IdentityPoolId }).promise();
    delete identityPool.CognitoIdentityProviders;
    await this.identity.updateIdentityPool(identityPool).promise();
  }

  async isDone(options) {
    options = options || {};
    const { config, service, stage } = options;
    const userPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    const clientId = await this.userPoolFacade.getClientId(service, stage, 'flash');
    const IdentityPoolId = await this.getIdentityPoolId(config.identityPoolName);
    const identityPool = await this.identity.describeIdentityPool({ IdentityPoolId }).promise();
    if (!identityPool.CognitoIdentityProviders) return false;
    if (identityPool.CognitoIdentityProviders.length === 0) return false;
    const expected = this.newCognitoIdentityProvider(userPoolId, clientId);
    for (let provider of identityPool.CognitoIdentityProviders) {
      if (
        provider.ProviderName === expected.ProviderName &&
        provider.ClientId === expected.ClientId &&
        provider.ServerSideTokenCheck === expected.ServerSideTokenCheck
      ) {
        return true;
      }
    }
    return false;
  }

  async getIdentityPoolId(identityPoolName) {
    let response, NextToken, pool;
    do {
      response = await this.identity.listIdentityPools({
        MaxResults: '60',
        NextToken
      }).promise();
      NextToken = response.NextToken;
      const pools = response.IdentityPools.filter(item => item.IdentityPoolName === identityPoolName);
      if (pools.length === 0) continue;
      else return pools[0].IdentityPoolId;
    } while (NextToken)
    throw new Error(`no identity pool for stage could be found: ${identityPoolName}`)
  }

  newCognitoIdentityProvider(userPoolId, clientId) {
    return {
      "ProviderName": `cognito-idp.us-west-2.amazonaws.com/${userPoolId}`,
      "ClientId": clientId,
      "ServerSideTokenCheck": false
    };
  }

}

module.exports = new CognitoIdentityPoolProvider();
module.exports.CognitoIdentityPoolProvider = CognitoIdentityPoolProvider;
