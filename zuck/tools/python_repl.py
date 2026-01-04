"""
Python REPL tool for code execution.
"""

from langchain_experimental.tools import PythonREPLTool


def get_python_repl_tool():
    """
    Get Python REPL tool for executing code.
    
    Returns:
        PythonREPLTool instance
        
    Note: This tool allows Python code execution. Use with caution.
    """
    return PythonREPLTool(
        description="""
        Execute Python code for data analysis and parsing.
        Useful for: parsing complex data, calculations, data transformations.
        Input should be valid Python code.
        Returns the output of the code execution.
        """
    )
