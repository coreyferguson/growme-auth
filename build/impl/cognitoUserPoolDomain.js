
const AWS = require('aws-sdk');
const BuildCommand = require('../BuildCommand');
const userPoolFacade = require('../aws-facades/cognitoUserPoolFacade');

class CognitoUserPoolDomain extends BuildCommand {

  constructor(options) {
    super(options);
    options = options || {};
    this.userPool = options.userPool
      || new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18', region: 'us-west-2' });
    this.userPoolFacade = options.userPoolFacade || userPoolFacade;
  }

  getName() {
    return 'cognitoUserPoolDomain';
  }

  async do(options) {
    options = options || {};
    const { config, service, stage } = options;
    const userPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    await this.userPool.createUserPoolDomain({
      Domain: this.getFullDomain(config.domain, config.subDomain, stage),
      UserPoolId: userPoolId,
      CustomDomainConfig: {
        CertificateArn: 'arn:aws:acm:us-east-1:863138142000:certificate/078933c7-2e00-415f-b964-ead49b37f915'
      }
    }).promise();
  }

  async undo(options) {
    options = options || {};
    const { config, service, stage } = options;
    const userPoolId = await this.userPoolFacade.getUserPoolId(service, stage);
    await this.userPool.deleteUserPoolDomain({
      Domain: this.getFullDomain(config.domain, config.subDomain, stage),
      UserPoolId: userPoolId
    }).promise();
  }

  async isDone(options) {
    options = options || {};
    const { config, stage } = options;
    const meta = await this.userPool.describeUserPoolDomain({
      Domain: this.getFullDomain(config.domain, config.subDomain, stage)
    }).promise();
    return !!meta.DomainDescription.Status;
  }

  getFullDomain(domain, subDomain, stage) {
    return stage === 'prod'
      ? `${subDomain}.${domain}`
      : `${subDomain}-${stage}.${domain}`;
  }

}

module.exports = new CognitoUserPoolDomain();
module.exports.CognitoUserPoolDomain = CognitoUserPoolDomain;
