
const { expect, sinon } = require('../../support/TestUtilities');
const BuildInvoker = require('../../../build/buildInvoker').BuildInvoker;
const StubCommand = require('../../support/stubs/build/StubCommand');

describe('buildInvoker', () => {

  const sandbox = sinon.createSandbox();

  const timeout = ms => new Promise(resolve => setTimeout(resolve, ms));

  function createStubbedRunList(ms) {
    const command1 = new StubCommand(1);
    const command2 = new StubCommand(2);
    return [command1, command2];
  }

  beforeEach(() => {
    sandbox.stub(console, 'info');
  });

  afterEach(() => {
    sandbox.restore();
  })

  it('deploy - runs and logs all commands', async () => {
    const defaultRunList = createStubbedRunList();
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test');
    expect(defaultRunList[0].do).to.be.calledOnce;
    expect(defaultRunList[0].undo).to.not.be.called;
    expect(defaultRunList[1].do).to.be.calledOnce;
    expect(defaultRunList[1].undo).to.not.be.called;
    expect(console.info).to.be.calledWith('Deploying StubCommand1');
    expect(console.info).to.be.calledWith('Deploying StubCommand2');
  });

  it('deploy - runs commands in order', async () => {
    const defaultRunList = createStubbedRunList();
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test');
    expect(defaultRunList[0].do).to.be.calledBefore(defaultRunList[1].do);
  });

  it('deploy - runs commands not yet done', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test');
    expect(defaultRunList[0].do).to.not.be.called;
    expect(defaultRunList[1].do).to.be.called;
  });

  it('deploy - stage passed to commands', async () => {
    const defaultRunList = createStubbedRunList();
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test');
    expect(defaultRunList[0].do).to.be.calledWith('test');
  });

  it('deploy - logs messages to console', async () => {
    const defaultRunList = createStubbedRunList();
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test');
  });

  it('deploy - runs defaultRunList when runList is empty array', async () => {
    const defaultRunList = createStubbedRunList();
    const runList = [];
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test', runList);
    expect(defaultRunList[0].do).to.be.called;
    expect(defaultRunList[1].do).to.be.called;
  });

  it('deploy - runs commands specified as runList argument', async () => {
    const defaultRunList = createStubbedRunList();
    const runList = [ createStubbedRunList()[1] ];
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.deploy('test', runList);
    expect(defaultRunList[0].do).to.not.be.called;
    expect(defaultRunList[1].do).to.not.be.called;
    expect(runList[0].do).to.be.called;
  });

  it('remove - runs all commands', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = defaultRunList[1]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test');
    expect(defaultRunList[0].undo).to.be.calledOnce;
    expect(defaultRunList[0].do).to.not.be.called;
    expect(defaultRunList[1].undo).to.be.calledOnce;
    expect(defaultRunList[1].do).to.not.be.called;
    expect(console.info).to.be.calledWith('Removing StubCommand1');
    expect(console.info).to.be.calledWith('Removing StubCommand2');
  });

  it('remove - runs commands in order', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = defaultRunList[1]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test');
    expect(defaultRunList[1].undo).to.be.calledBefore(defaultRunList[0].undo);
  });

  it('remove - runs commands not yet done', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[1]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test');
    expect(defaultRunList[0].undo).to.not.be.called;
    expect(defaultRunList[1].undo).to.be.called;
  });


  it('remove - stage passed to commands', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = true;
    defaultRunList[1]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test');
    expect(defaultRunList[1].undo).to.be.calledWith('test');
  });

  it('remove - runs defaultRunList when runList is empty array', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = true;
    defaultRunList[1]._isDone = true;
    const runList = [];
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test', runList);
    expect(defaultRunList[0].undo).to.be.called;
    expect(defaultRunList[1].undo).to.be.called;
  });

  it('remove - runs commands specified as runList argument', async () => {
    const defaultRunList = createStubbedRunList();
    defaultRunList[0]._isDone = true;
    defaultRunList[1]._isDone = true;
    const runList = [ createStubbedRunList()[1] ];
    runList[0]._isDone = true;
    const invoker = new BuildInvoker({ defaultRunList });
    await invoker.remove('test', runList);
    expect(defaultRunList[0].undo).to.not.be.called;
    expect(defaultRunList[1].undo).to.not.be.called;
    expect(runList[0].undo).to.be.called;
  });

});
