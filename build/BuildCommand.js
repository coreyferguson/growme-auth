
class BuildCommand {

  getName() {
    throw new Error("BuildCommand.getName() must be overridden.");
  }

  /**
   * Perform an operation. Implementation details must be specified by child classes.
   * @returns Promise
   */
  async do(stage) {
    throw new Error("BuildCommand.do() must be overridden.");
  }

  /**
   * Undoes a previous applied operation. Implementation details must be specified by
   * child classes.
   * @returns Promise
   */
  async undo(stage) {
    throw new Error("BuildCommand.undo() must be overridden.");
  }

  /**
   * Checks if this operation was previously applied. Implementation details must be
   * specified by child classes.
   * @returns Promise
   */
  async isDone(stage) {
    throw new Error("BuildCommand.isDone() must be overridden.");
  }

}

module.exports = BuildCommand;
