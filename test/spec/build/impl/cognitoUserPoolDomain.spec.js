
const CognitoUserPoolDomain = require('../../../../build/impl/cognitoUserPoolDomain').CognitoUserPoolDomain;
const userPool = require('../../../support/stubs/aws-sdk/stubCognitoIdentityServiceProvider');
const userPoolFacade = require('../../../support/stubs/build/aws-facades/stubCognitoUserPoolFacade');
const { expect, sinon } = require('../../../support/TestUtilities');

describe('cognitoUserPoolDomain', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('name is defined', () => {
    const command = new CognitoUserPoolDomain({ userPool });
    const name = command.getName();
    expect(name).to.not.be.null;
  })

  it('isDone - user pool does not exist', async () => {
    const command = new CognitoUserPoolDomain({ userPool });
    const response = { DomainDescription: {} };
    sandbox
      .stub(userPool, 'describeUserPoolDomain')
      .returns({ promise: () => Promise.resolve(response) });
    const isDone = await command.isDone('test');
    expect(isDone).to.be.false;
  });

  it('do - unknown error', async () => {
    const command = new CognitoUserPoolDomain({ userPool, userPoolFacade });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('us-west-2_aBcDeFgHi');
    sandbox.stub(userPool, 'createUserPoolDomain').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.do('test')).to.eventually.be.rejectedWith('oops');
  });

  it('do - CNAMEAlreadyExists', async () => {
    const command = new CognitoUserPoolDomain({ userPool, userPoolFacade });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('us-west-2_aBcDeFgHi');
    sandbox.stub(userPool, 'createUserPoolDomain').returns({ promise: () => Promise.reject(new Error('InvalidParameterException: One or more of the CNAMEs you provided are already associated with a different resource. (Service: AmazonCloudFront; Status Code: 409; Error Code: CNAMEAlreadyExists; Request ID: d67bedf3-cadd-11e9-a61f-c578a76c3695)')) });
    sandbox.stub(console, 'error');
    await expect(command.do('test')).to.eventually.be.rejectedWith('CNAMEAlreadyExists');
  });

  it('undo - unknown error', async () => {
    const command = new CognitoUserPoolDomain({ userPool, userPoolFacade });
    sandbox.stub(userPoolFacade, 'getUserPoolId').returns('us-west-2_aBcDeFgHi');
    sandbox.stub(userPool, 'deleteUserPoolDomain').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.undo('test')).to.eventually.be.rejectedWith('oops');
  });

});
