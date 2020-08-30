class Logger(object):

    """Base print loggging class

    Attributes:
        verbose (bool): Should print debug messages or not
    """

    def __init__(self, verbose = False):
        """Summary

        Args:
            verbose (bool, optional): Description
        """
        self.verbose = verbose

    def SetVerbosity(self, verbose):
        """Change the verbosity of the logger

        Args:
            verbose (bool): Turn verbose on(True) or off(False)
        """
        self.verbose = verbose

    def Log(self, level, message):
        """Summary

        Args:
            level (str): Log level
            message (str): Message to print
        """
        # Don't print debug messages if we are not verbose
        if level == "DEBUG" and not self.verbose:
            return

        print("{}: {}".format(str(level), str(message)))

        # Exit if it is fatal
        if level == "FATAL":
            exit(1)

logger = Logger()