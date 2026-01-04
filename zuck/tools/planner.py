"""
Planning tool for complex multi-step tasks.
Maintains state in session memory.
"""

import logging
import json
from typing import List, Optional
from langchain.tools import tool
from zuck.tools.registry import get_session_memory

logger = logging.getLogger('zuck_agent')


@tool
def create_plan(steps: List[str]) -> str:
    """
    Create a structured plan for a complex task and store it in memory.
    
    Args:
        steps: List of steps to execute (e.g. ["Scan ports", "Enumerate services"])
        
    Returns:
        The formatted plan with ID.
    """
    memory = get_session_memory()
    
    # Create plan object
    plan = {
        "steps": [{"id": i+1, "task": step, "status": "pending"} for i, step in enumerate(steps)],
        "current_step": 1,
        "total_steps": len(steps)
    }
    
    # Store in memory
    memory["current_plan"] = plan
    
    # Format output
    output = ["📝 **ACTIVE PLAN INITIALIZED:**"]
    for step in plan["steps"]:
        output.append(f"[ ] {step['id']}. {step['task']}")
        
    return "\n".join(output) + "\n\nI will track progress using `update_plan_step`."


@tool
def update_plan_step(step_id: int, status: str, result: str = "") -> str:
    """
    Update the status of a plan step.
    
    Args:
        step_id: The step number (1-based)
        status: 'done', 'failed', or 'in_progress'
        result: Brief summary of the result (optional)
        
    Returns:
        Updated plan status.
    """
    memory = get_session_memory()
    plan = memory.get("current_plan")
    
    if not plan:
        return "❌ No active plan found. Use `create_plan` first."
        
    # Find step
    if step_id < 1 or step_id > len(plan["steps"]):
        return f"❌ Invalid step ID: {step_id}"
        
    step = plan["steps"][step_id - 1]
    step["status"] = status
    if result:
        step["result"] = result
        
    # Valid status icons
    icons = {"done": "✅", "failed": "❌", "in_progress": "🔄", "pending": "⬜"}
    icon = icons.get(status, "❓")
    
    # Check if plan is complete
    all_done = all(s["status"] == "done" for s in plan["steps"])
    
    if all_done:
        return f"{icon} Step {step_id} updated: {status}\n🎉 **PLAN COMPLETE!** All steps finished."
        
    # Suggest next step
    next_step = None
    for s in plan["steps"]:
        if s["status"] == "pending":
            next_step = s
            break
            
    response = f"{icon} Step {step_id} updated: {status}"
    if next_step:
        response += f"\n👉 **NEXT UP:** Step {next_step['id']}: {next_step['task']}"
        
    return response


@tool
def get_current_plan() -> str:
    """
    Retrieve the current plan status.
    
    Returns:
        Formatted plan with current status of all steps.
    """
    memory = get_session_memory()
    plan = memory.get("current_plan")
    
    if not plan:
        return "No active plan."
        
    icons = {"done": "✅", "failed": "❌", "in_progress": "🔄", "pending": "⬜"}
    
    output = ["� **CURRENT PLAN STATUS:**"]
    for step in plan["steps"]:
        icon = icons.get(step["status"], "⬜")
        line = f"{icon} {step['id']}. {step['task']}"
        if step.get("result"):
            line += f" -> {step['result']}"
        output.append(line)
        
    return "\n".join(output)
