
const CognitoUserPoolFacade = require('../../../../build/aws-facades/cognitoUserPoolFacade').CognitoUserPoolFacade;
const userPool = require('../../../support/stubs/aws-sdk/stubCognitoIdentityServiceProvider');
const { expect, sinon } = require('../../../support/TestUtilities');

describe('CognitoUserPoolFacade', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('getUserPoolId - success', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    const response = {
      "UserPools": [
        {
          "CreationDate": "2019-08-30T03:28:39.320Z",
          "Id": "us-west-2_aBcDeFgHi",
          "LambdaConfig": {},
          "LastModifiedDate": "2019-08-30T03:28:39.320Z",
          "Name": "overattribution-auth-test"
        }
      ]
    };
    sandbox.stub(userPool, 'listUserPools').returns({ promise: () => Promise.resolve(response) });
    const userPoolId = await command.getUserPoolId('test');
    expect(userPoolId).to.equal('us-west-2_aBcDeFgHi');
  });

  it('getUserPoolId - unknown error', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(userPool, 'listUserPools').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.getUserPoolId('test')).to.eventually.be.rejected;
  });

  it('getUserPoolId - no pools', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    const response = { "UserPools": [] };
    sandbox.stub(userPool, 'listUserPools').returns({ promise: () => Promise.resolve(response) });
    await expect(command.getUserPoolId('test')).to.eventually.be.rejectedWith('No User Pool');
  });

  it('getUserPoolId - paginated results', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(command, 'getUserPoolName').returns('overattribution-auth-test');
    const stubResponse = (NextToken, Name) => ({
      UserPools: [{
        CreationDate: '2019-08-30T03:28:39.320Z',
        Id: `${Name}-IdValue`,
        LambdaConfig: {},
        LastModifiedDate: '2019-08-30T03:28:39.320Z',
        Name
      }],
      NextToken
    });
    sandbox.stub(userPool, 'listUserPools')
      .onCall(0).returns({ promise: () => stubResponse('page2', 'overattribution-auth-test2') })
      .onCall(1).returns({ promise: () => stubResponse('page3', 'overattribution-auth-test3') })
      .onCall(2).returns({ promise: () => stubResponse(undefined, 'overattribution-auth-test') });
    const userPoolId = await command.getUserPoolId('test');
    expect(userPoolId).to.equal('overattribution-auth-test-IdValue')
    expect(userPool.listUserPools.callCount).to.equal(3);
    expect(userPool.listUserPools.getCall(0).args[0].NextToken).to.be.undefined;
    expect(userPool.listUserPools.getCall(1).args[0].NextToken).to.equal('page2');
    expect(userPool.listUserPools.getCall(2).args[0].NextToken).to.equal('page3');
  });

  it('getClientId - success', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(command, 'getUserPoolId');
    sandbox.stub(userPool, 'listUserPoolClients').returns({ promise: () => ({
      UserPoolClients: [{  ClientId: 'ClientIdValue', ClientName: 'clientNameValue' }]
    }) });
    const id = await command.getClientId('test', 'clientNameValue');
    expect(id).to.equal('ClientIdValue');
  });

  it('getClientId - paginated results', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(command, 'getUserPoolId');
    const stubResponse = (ClientId, ClientName, NextToken) =>
      ({ UserPoolClients: [{  ClientId, ClientName }], NextToken });
    sandbox.stub(userPool, 'listUserPoolClients')
      .onCall(0).returns({ promise: () => stubResponse('clientIdValue1', 'clientNameValue1', 'page2') })
      .onCall(1).returns({ promise: () => stubResponse('clientIdValue2', 'clientNameValue2', 'page3') })
      .onCall(2).returns({ promise: () => stubResponse('clientIdValue3', 'clientNameValue3', undefined) });
    const id = await command.getClientId('test', 'clientNameValue3');
    expect(id).to.equal('clientIdValue3');
    expect(userPool.listUserPoolClients.callCount).to.equal(3);
    expect(userPool.listUserPoolClients.getCall(0).args[0].NextToken).to.be.undefined;
    expect(userPool.listUserPoolClients.getCall(1).args[0].NextToken).to.equal('page2');
    expect(userPool.listUserPoolClients.getCall(2).args[0].NextToken).to.equal('page3');
  });

  it('getClientId - no clients', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(command, 'getUserPoolId');
    sandbox.stub(userPool, 'listUserPoolClients').returns({ promise: () => ({ UserPoolClients: [] }) });
    await expect(command.getClientId('test', 'clientNameValue')).to.eventually.be.rejected;
  });

  it('getClientId - no client found', async () => {
    const command = new CognitoUserPoolFacade({ userPool });
    sandbox.stub(command, 'getUserPoolId');
    sandbox.stub(userPool, 'listUserPoolClients').returns({ promise: () => ({
      UserPoolClients: [ { ClientName: 'anotherClient1' }, { ClientName: 'anotherClient2' } ]
    }) });
    await expect(command.getClientId('test', 'clientNameValue')).to.eventually.be.rejected;
  });

});

