
const defaultRunList = require('./defaultBuildCommandRunList');

class BuildInvoker {

  constructor(options) {
    options = options || {};
    this.defaultRunList = options.defaultRunList || defaultRunList;
  }

  /**
   * @param {String} stage serverless stage
   * @param {Array.<String>} runList Collection of commands to be run from `build/impl` folder.
   * @param {Object} log logger
   * @param {String} service serverless service name
   * @param {Object} config custom config provided in serverless.yml
   */
  async deploy(options) {
    const log = options.log;
    const runList = options.runList && runList.length>0 ? runList : this.defaultRunList;
    for (let command of runList) {
      const isDone = await command.isDone(options);
      if (!isDone) {
        log('Deploying ' + command.getName());
        await command.do(options);
      } else {
        log(command.getName() + ' already done. Skipping.');
      }
    }
  }

  /**
   * @param {String} stage serverless stage
   * @param {Array.<String>} runList Collection of commands to be run from `build/impl` folder.
   * @param {Object} log logger
   * @param {String} service serverless service name
   */
  async remove(options) {
    const log = options.log;
    const runList = options.runList && runList.length>0 ? runList : this.defaultRunList;
    let command, isDone;
    for (let i=runList.length-1; i>=0; i--) {
      command = runList[i];
      isDone = await command.isDone(options);
      if (isDone) {
        log('Removing ' + command.getName());
        await command.undo(options);
      } else {
        log(command.getName() + ' already removed. Skipping.');
      }
    }
  }

}

module.exports = new BuildInvoker();
module.exports.BuildInvoker = BuildInvoker;
