
const BuildCommand = require('../../../build/BuildCommand');
const { expect } = require('../../support/TestUtilities');

describe('BuildCommand', () => {

  it('command.getName() must be overridden', () => {
    class CommandImpl extends BuildCommand {};
    const command = new CommandImpl();
    // error because it wasn't implemented yet
    expect(() => command.getName()).to.throw();
    CommandImpl.prototype.getName = () => Promise.resolve();
    // no error because it was implemented now
    expect(command.getName()).to.be.fulfilled;
  });

  it('command.do() must be overridden', async () => {
    class CommandImpl extends BuildCommand {};
    const command = new CommandImpl();
    // error because it wasn't implemented yet
    await expect(command.do()).to.be.rejected;
    CommandImpl.prototype.do = () => Promise.resolve();
    // no error because it was implemented now
    await expect(command.do()).to.be.fulfilled;
  });

  it('command.undo() must be overridden', async () => {
    class CommandImpl extends BuildCommand {};
    const command = new CommandImpl();
    // error because it wasn't implemented yet
    await expect(command.undo()).to.be.rejected;
    CommandImpl.prototype.undo = () => Promise.resolve();
    // no error because it was implemented now
    await expect(command.undo()).to.be.fulfilled;
  });

  it('command.isDone() must be overridden', async () => {
    class CommandImpl extends BuildCommand {};
    const command = new CommandImpl();
    // error because it wasn't implemented yet
    await expect(command.isDone()).to.be.rejected;
    CommandImpl.prototype.isDone = () => Promise.resolve();
    // no error because it was implemented now
    await expect(command.isDone()).to.be.fulfilled;
  });

});
