
const { expect, sinon } = require('../../../support/TestUtilities');
const CognitoIdentityPoolProvider = require('../../../../build/impl/cognitoIdentityPoolProvider').CognitoIdentityPoolProvider;
const identity = require('../../../support/stubs/aws-sdk/stubCognitoIdentity');
const userPoolFacade = require('../../../../build/aws-facades/cognitoUserPoolFacade');

describe('cognitoIdentityPoolProvider', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('getIdentityPoolId - get identity pool for correct stage', async () => {
    const command = new CognitoIdentityPoolProvider({ identity });
    sandbox.stub(identity, 'listIdentityPools').returns({ promise: () => Promise.resolve({
      IdentityPools: [{
          IdentityPoolId: 'us-west-2:1a2345b6-78cd-90ef-gh12-i3jk45lm6n7o',
          IdentityPoolName: 'overattribution_auth_prod'
      }, {
        IdentityPoolId: 'us-west-2:123ab456-789c-01de-23f4-5gh6i7890jk1',
        IdentityPoolName: 'overattribution_auth_test'
      }]
    }) });
    // {"IdentityPools":[{"IdentityPoolId":"us-west-2:3e2253f7-17ab-42ad-aa81-b6bc15ae9f1d","IdentityPoolName":"overattribution_auth_prod"},{"IdentityPoolId":"us-west-2:904ac209-681d-40df-85e8-6bf2d6976bb3","IdentityPoolName":"overattribution_auth_dev"}]}
    const id = await command.getIdentityPoolId('test');
    await expect(id).to.equal('us-west-2:123ab456-789c-01de-23f4-5gh6i7890jk1');
  });

  it('getIdentityPoolId - throw error when no identity pool exists', async () => {
    const command = new CognitoIdentityPoolProvider({ identity });
    sandbox.stub(identity, 'listIdentityPools').returns({ promise: () => Promise.resolve({
      IdentityPools: []
    }) });
    await expect(command.getIdentityPoolId('test')).to.eventually.be.rejected;
  });

  it('getIdentityPoolId - pagination', async () => {
    const stage = 'test';
    const command = new CognitoIdentityPoolProvider({ identity });
    const stubResponse = (IdentityPoolId, IdentityPoolName, NextToken) => ({
      IdentityPools: [{ IdentityPoolId, IdentityPoolName }],
      NextToken
    });
    sandbox.stub(identity, 'listIdentityPools')
      .onCall(0).returns({ promise: () => stubResponse('id1', 'overattribution_auth_test1', 'page2') })
      .onCall(1).returns({ promise: () => stubResponse('id2', 'overattribution_auth_test2', 'page3') })
      .onCall(2).returns({ promise: () => stubResponse('id3', 'overattribution_auth_test', 'undefined') });
    const id = await command.getIdentityPoolId('test');
    expect(identity.listIdentityPools.callCount).to.equal(3);
    expect(identity.listIdentityPools.getCall(0).args.NextToken).to.be.undefined;
    expect(identity.listIdentityPools.getCall(1)).to.have.nested.property('args[0].NextToken', 'page2');
    expect(identity.listIdentityPools.getCall(2)).to.have.nested.property('args[0].NextToken', 'page3');
    expect(id).to.equal('id3');
  });

  it('getIdentityPoolId - throw error when identity pool cannot be found', async () => {
    const stage = 'test';
    const command = new CognitoIdentityPoolProvider({ identity });
    const stubResponse = (IdentityPoolId, IdentityPoolName, NextToken) => ({
      IdentityPools: [{ IdentityPoolId, IdentityPoolName }],
      NextToken
    });
    sandbox.stub(identity, 'listIdentityPools')
      .onCall(0).returns({ promise: () => stubResponse('id1', 'overattribution_auth_test1', 'page2') })
      .onCall(1).returns({ promise: () => stubResponse('id2', 'overattribution_auth_test2', 'page3') })
      .onCall(2).returns({ promise: () => stubResponse('id3', 'overattribution_auth_test3', undefined) });
    await expect(command.getIdentityPoolId('test')).to.eventually.be.rejected;
  });

  it('do - compiles identity pool id, client id and user pool id', async () => {
    const command = new CognitoIdentityPoolProvider({ identity, userPoolFacade });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('us-west-2_aB1c2D3eF')
    sandbox.stub(userPoolFacade, 'getClientId').returns('1a2b3c4defghi5jklmnopqr6st');
    const identityPoolId = 'us-west-2:1a2345fb-78cd-90ef-gh12-i4jk56lm7n8o';
    sandbox.stub(command, 'getIdentityPoolId').returns(identityPoolId);
    const identityPool = {
      IdentityPoolId: identityPoolId,
      IdentityPoolName: 'overattribution_auth_test',
      AllowUnauthenticatedIdentities: true,
      IdentityPoolTags: {}
    };
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => Promise.resolve(identityPool) });
    const spy = sandbox.stub(identity, 'updateIdentityPool').returns({ promise: () => Promise.resolve() });
    await command.do('test');
    expect(spy.getCall(0)).to.be.calledWith({
      IdentityPoolId: identityPoolId,
      IdentityPoolName: "overattribution_auth_test",
      AllowUnauthenticatedIdentities: true,
      CognitoIdentityProviders: [{
        ClientId: "1a2b3c4defghi5jklmnopqr6st",
        ProviderName: "cognito-idp.us-west-2.amazonaws.com/us-west-2_aB1c2D3eF",
        ServerSideTokenCheck: false
      }],
      IdentityPoolTags: {  }
    });
  });

  it('isDone - null identityPool.CognitoIdentityProviders', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({}) });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('isDone - identityPool.CognitoIdentityProviders.length === 0', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({ CognitoIdentityProviders: [] }) });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('isDone - true', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({ CognitoIdentityProviders: [{
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    }] }) });
    sandbox.stub(command, 'newCognitoIdentityProvider').returns({
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    });
    await expect(command.isDone('test')).to.eventually.be.true;
  });

  it('isDone - false - no matching ProviderName', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({ CognitoIdentityProviders: [{
      ProviderName: 'ProviderNameValue1',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    }] }) });
    sandbox.stub(command, 'newCognitoIdentityProvider').returns({
      ProviderName: 'ProviderNameValue2',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('isDone - false - no matching ClientIdValue', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({ CognitoIdentityProviders: [{
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue1',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    }] }) });
    sandbox.stub(command, 'newCognitoIdentityProvider').returns({
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue2',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue'
    });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

  it('isDone - false - no matching ServerSideTokenCheckValue', async () => {
    const command = new CognitoIdentityPoolProvider({ userPoolFacade, identity });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('userPoolIdValue');
    sandbox.stub(userPoolFacade, 'getClientId').returns('clientIdValue');
    sandbox.stub(command, 'getIdentityPoolId').returns('identityPoolId');
    sandbox.stub(identity, 'describeIdentityPool').returns({ promise: () => ({ CognitoIdentityProviders: [{
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue1'
    }] }) });
    sandbox.stub(command, 'newCognitoIdentityProvider').returns({
      ProviderName: 'ProviderNameValue',
      ClientId: 'ClientIdValue',
      ServerSideTokenCheck: 'ServerSideTokenCheckValue2'
    });
    await expect(command.isDone('test')).to.eventually.be.false;
  });

});
