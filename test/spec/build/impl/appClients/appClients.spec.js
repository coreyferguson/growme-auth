
const AppClients = require('../../../../../build/impl/appClients/appClients').AppClients;
const userPool = require('../../../../support/stubs/aws-sdk/stubCognitoIdentityServiceProvider');
const userPoolFacade = require('../../../../support/stubs/build/aws-facades/stubCognitoUserPoolFacade');
const { expect, sinon } = require('../../../../support/TestUtilities');

describe('appClients', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('isDone - true', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        "UserPoolClients": [
          { "ClientId": "1", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "one" },
          { "ClientId": "2", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "two" }
        ]
      })
    });
    await expect(command.isDone('test')).to.eventually.be.true;
  });

  it('isDone - false - missing one client', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        "UserPoolClients": [
          { "ClientId": "2", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "two" }
        ]
      })
    });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('isDone - false - one extra client', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        "UserPoolClients": [
          { "ClientId": "1", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "one" },
          { "ClientId": "2", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "two" },
          { "ClientId": "3", "UserPoolId": "us-west-2_abCdEfG12", "ClientName": "three" }
        ]
      })
    });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('do - create missing clients', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade,
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        UserPoolClients: [ { ClientName: "one" } ]
      })
    });
    sandbox.stub(command, 'createClient');
    sandbox.stub(command, 'deleteClient');
    await command.do('test');
    expect(command.createClient).to.be.calledOnce;
    expect(command.deleteClient).to.not.be.called;
  });

  it('do - delete extra clients', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        UserPoolClients: [ { ClientName: "one" }, { ClientName: "two" }, { ClientName: "deleteme" } ]
      })
    });
    sandbox.stub(command, 'createClient');
    sandbox.stub(command, 'deleteClient');
    await command.do('test');
    expect(command.createClient).to.not.be.called;
    expect(command.deleteClient).to.be.calledOnce;
  });

  it('undo - delete all clients', async () => {
    const command = new AppClients({
      userPool,
      userPoolFacade
    });
    sandbox.stub(command, 'getAppClientsConfig').returns(createAppClientsConfig());
    sandbox.stub(userPool, 'listUserPoolClients').returns({
      promise: () => Promise.resolve({
        UserPoolClients: [ { ClientName: "one" }, { ClientName: "two" } ]
      })
    });
    sandbox.stub(command, 'createClient');
    sandbox.stub(command, 'deleteClient');
    await command.undo('test');
    expect(command.deleteClient).to.be.calledTwice;
  });

  it('createClient - interpolated with doT template', async () => {
    const command = new AppClients({ userPool });
    sandbox.stub(userPool, 'createUserPoolClient').returns({ promise: () => Promise.resolve() });
    const config = {
      url: "https://client{{=it.stage === 'prod' ? '' : `-${it.stage}`}}.overattribution.com/oauth/callback"
    };
    await command.createClient('test', config, 'us-west-2_abCdEfG12');
    expect(userPool.createUserPoolClient.getCall(0)).to.be.calledWith({
      url: "https://client-test.overattribution.com/oauth/callback",
      UserPoolId: 'us-west-2_abCdEfG12'
    });
    await command.createClient('prod', config, 'us-west-2_abCdEfG12');
    expect(userPool.createUserPoolClient.getCall(1)).to.be.calledWith({
      url: "https://client.overattribution.com/oauth/callback",
      UserPoolId: 'us-west-2_abCdEfG12'
    });
  });

  it('getAppClientsConfig');

});

function createAppClientsConfig() {
  return {
    appClients: [
      { ClientName: 'one' },
      { ClientName: 'two' }
    ]
  };
};
