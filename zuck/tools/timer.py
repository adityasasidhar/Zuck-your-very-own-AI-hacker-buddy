"""Timer tool to let the agent pause execution for N seconds.

This is implemented as a synchronous sleep so that the ReAct loop
resumes automatically once the timer completes.
"""

import time

from langchain.tools import tool


@tool
def wait_timer(seconds: int, reason: str = "") -> str:
    """Pause execution for a number of seconds, then resume.

    This blocks the current agent run for the requested duration and only
    returns after the time has elapsed, so the model can continue reasoning
    *after* the delay.

    Args:
        seconds: Number of seconds to wait (1 to MAX_TIMER_SECONDS).
        reason: Optional human-readable reason for the delay, included in
            the return text for additional context.

    Returns:
        A short message indicating that the timer has completed.
    """

    MAX_TIMER_SECONDS = 3600

    if seconds <= 0:
        return "Timer duration must be a positive integer number of seconds."

    if seconds > MAX_TIMER_SECONDS:
        seconds = MAX_TIMER_SECONDS
        clamped = True
    else:
        clamped = False

    time.sleep(seconds)

    base_msg = f"Timer completed after {seconds} seconds."
    if clamped:
        base_msg += " (duration was clamped to the maximum allowed)"

    if reason:
        return f"{base_msg} Reason: {reason}"

    return base_msg
