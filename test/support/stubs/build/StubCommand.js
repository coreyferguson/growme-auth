
const BuildCommand = require('../../../../build/BuildCommand');
const sinon = require('sinon');

const timeout = ms => new Promise(resolve => setTimeout(resolve, ms));

class StubCommand extends BuildCommand {

  constructor(id) {
    super();
    this._isDone = false;
    id = id || '';

    this.getName = sinon.stub().callsFake(() => {
      return "StubCommand" + id;
    });

    this.do = sinon.stub().callsFake(() => {
      this._isDone = true;
      return timeout(1);
    });

    this.undo = sinon.stub().callsFake(() => {
      this._isDone = false;
      return timeout(1);
    });

    this.isDone = sinon.stub().callsFake(() => {
      return timeout(1).then(() => this._isDone);
    });
  }

}

module.exports = StubCommand;
