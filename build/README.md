
# Build

## Summary

These scripts are used for build and deployment. A Command Design Pattern is used to provide
do() and undo() operations.

## Creating a new command

Create a new file in the `impl` folder. Boilerplate:

```
const BuildCommand = require('../BuildCommand');

class MyCommand extends BuildCommand {

  async do(stage) {
    // do something here
  }

  async undo(stage) {
    // undo what you did up there
  }

  async isDone(stage) {
    return false; // determine if you've already done something up there
  }

}

module.exports = new MyCommand();
module.exports.MyCommand = MyCommand;
```

Require this module in `defaultBuildCommandRunList.js`.
