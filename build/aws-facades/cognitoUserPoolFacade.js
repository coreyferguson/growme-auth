
const AWS = require('aws-sdk');

class CognitoUserPoolFacade {

  constructor(options) {
    options = options || {};
    this.userPool = options.userPool
      || new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18', region: 'us-west-2' });
  }

  async getUserPoolId(service, stage) {
    const userPoolName = this.getUserPoolName(service, stage);
    let data, NextToken, userPoolId;
    do {
      data = await this.userPool.listUserPools({ MaxResults: 60, NextToken }).promise();
      for (let userPool of data.UserPools) {
        if (userPool.Name === userPoolName) {
          userPoolId = userPool.Id;
          break;
        }
      }
      NextToken = data.NextToken;
    } while (!userPoolId && NextToken);
    if (!userPoolId) throw new Error(`No User Pool found in stage=${stage}`);
    return userPoolId;
  }

  getUserPoolName(service, stage) {
    return `${service}-${stage}`;
  }

  async getClientId(service, stage, clientName) {
    const UserPoolId = await this.getUserPoolId(service, stage);
    let clientId, response, NextToken;
    do {
      response = await this.userPool.listUserPoolClients({ UserPoolId, NextToken }).promise();
      for (let client of response.UserPoolClients) {
        if (client.ClientName === clientName) return client.ClientId;
      }
      NextToken = response.NextToken;
    } while (!clientId && NextToken);
    throw new Error(`No client with name found: ${clientName}`);
  }

}

module.exports = new CognitoUserPoolFacade();
module.exports.CognitoUserPoolFacade = CognitoUserPoolFacade;
