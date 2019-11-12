'use strict';

const AWS = require('aws-sdk');
const buildInvoker = require('../build/buildInvoker');

class ServerlessPlugin {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;
    this.ssm = new AWS.SSM({ apiVersion: '2014-11-06', region: serverless.service.provider.region });

    this.commands = {
      'set-provider-secret': {
        usage: 'Sets a secret value in AWS Systems Manager Parameter Store',
        lifecycleEvents: ['set-secret'],
        options: {
          'client-id': {
            usage: 'Google Identity Provider Client Id',
            required: true
          },
          'secret': {
            usage: 'Google Identity Provider Secret',
            required: true
          }
        },
      },
    };

    this.hooks = {
      'set-provider-secret:set-secret': this.setProviderSecret.bind(this),
      'after:deploy:deploy': this.afterDeploy.bind(this),
      'before:remove:remove': this.beforeRemove.bind(this),
    };
  }

  async setProviderSecret() {
    const stage = this.serverless.service.provider.stage;
    const service = this.serverless.service.service;
    const clientId = this.options['client-id'];
    const secret = this.options['secret'];
    await this.putParameter(`/${service}/${stage}/COGNITO_USER_POOL_IDP_GOOGLE_CLIENT_ID`, clientId);
    await this.putParameter(`/${service}/${stage}/COGNITO_USER_POOL_IDP_GOOGLE_SECRET`, secret);
  }

  putParameter(name, value) {
    return new Promise((resolve, reject) => {
      this.ssm.putParameter({
        Name: name,
        Type: 'SecureString',
        Value: value,
        Overwrite: true
      }, (err, data) => {
        if (err) reject(err);
        else resolve(data);
        if (!err) this.serverless.cli.log(`Successfully saved '${name}' to Parameter Store`);
      });
    });
  }

  async afterDeploy() {
    const stage = this.serverless.service.provider.stage;
    const service = this.serverless.service.service;
    const config = this.serverless.service.custom.oauthProvider;
    await buildInvoker.deploy({
      service,
      stage,
      log: this.serverless.cli.log.bind(this.serverless.cli),
      config
    });
  }

  async beforeRemove() {
    const stage = this.serverless.service.provider.stage;
    const service = this.serverless.service.service;
    const config = this.serverless.service.custom.oauthProvider;
    await buildInvoker.remove({
      service,
      stage,
      log: this.serverless.cli.log.bind(this.serverless.cli),
      config
    });
  }
}

module.exports = ServerlessPlugin;
